#include <getopt.h>
#include <glib.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "agency.h"
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "handshake.h"
#include "proto_stk.h"
#include "service.h"
#include "tof.h"

static bool empty_svc_loop(int);

int main(int argc, char *argv[])
{
	int opt, fd;
	gsize path_len;
	char *path = NULL;
	struct sockaddr_un sa;
	int retval = EXIT_FAILURE;

	while ((opt = getopt(argc, argv, "u:")) != -1) {
		switch (opt) {
		case 'u':
			path_len = strlen(optarg) + 1; /* NUL */
			if (path_len > sizeof(sa.sun_path))
				return EXIT_FAILURE;
			memset(&sa, 0, sizeof(sa));
			sa.sun_family = AF_UNIX;
			path = &sa.sun_path[0];
			(void)!strncpy(path, optarg, sizeof(sa.sun_path));
			break;
		default:
			return EXIT_FAILURE;
		}
	}
	if (!path) /* detects whether the -u option got passed */
		return EXIT_FAILURE;
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return EXIT_FAILURE;
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto out_shutdown;
	if (!empty_svc_loop(fd))
		goto out_shutdown;
	retval = EXIT_SUCCESS;
out_shutdown:
	(void)!shutdown(fd, SHUT_RDWR);
	(void)!close(fd);
	return retval;
}

static bool
fd_wait_readable(int fd)
{
	struct pollfd pollfd = {
		.fd = fd,
		.events = POLLIN,
		.revents = 0,
	};

	return poll(&pollfd, 1, -1) >= 0;
}

static bool
fd_wait_writable(int fd)
{
	struct pollfd pollfd = {
		.fd = fd,
		.events = POLLOUT,
		.revents = 0,
	};

	return poll(&pollfd, 1, -1) >= 0;
}

static int
send_tof(struct tof_msg *tof, int fd)
{
	int retval = RETVAL_FAILURE;
	unsigned char *buf, *cur_buf;
	size_t sz, cur_sz;
	ssize_t ret_sz;

	if (!(buf = ctf_proto_stk_encode(mpn_trace_objects, (union msg *)tof, &sz)))
		return RETVAL_FAILURE;
	/* This is an awkward enough pattern that the API should change. */
	cur_buf = buf;
	cur_sz = sz;
retry_send:
	fd_wait_writable(fd);
	ret_sz = send(fd, cur_buf, cur_sz, MSG_CONFIRM | MSG_NOSIGNAL);
	if (ret_sz == (ssize_t)cur_sz)
		retval = RETVAL_SUCCESS;
	else if (!ret_sz && !errno) { /* EOF */
		retval = RETVAL_SUCCESS;
		goto out_free_buf;
	} else if (!ret_sz && errno != EAGAIN && errno != EWOULDBLOCK)
		goto out_free_buf;
	else if (ret_sz >= 0) {
		cur_buf = &cur_buf[MIN(cur_sz, ret_sz)];
		cur_sz -= MIN(cur_sz, ret_sz);
		(void)!sched_yield();
		goto retry_send;
	}
out_free_buf:
	free(buf);
	return retval;
}

static enum svc_result
send_done(int fd)
{
	struct tof_msg done_msg = {
		.tof_msg_type = tof_done,
		.tof_msg_body = {
			.request = {
				.tof_blocking = false,
				.tof_nr_obj   = 0,
			},
		},
	};
	ctf_msg(empty_loop, "entered send_done()\n");
	if (send_tof(&done_msg, fd) != RETVAL_SUCCESS) {
		ctf_msg(unix, "service_send_tof() failed\n");
		return svc_progress_fail;
	}
	ctf_msg(empty_loop, "successful return from send_done()\n");
	return svc_progress_send;
}

struct ctf_proto_stk_decode_result *
recv_tof(int fd)
{
	struct ctf_proto_stk_decode_result *cpsdr = NULL;

	if (!(cpsdr = ctf_proto_stk_decode(fd))) {
		ctf_msg(empty_loop, "ctf_proto_stk_decode() failed\n");
		return NULL;
	}
	return cpsdr;
}

static bool
send_empty_reply(int fd)
{
	bool retval = false;
	unsigned char *buf, *cur_buf;
	size_t sz, cur_sz;
	ssize_t ret_sz;
	struct tof_msg empty_reply = {
		.tof_msg_type = tof_reply,
		.tof_msg_body = {
			.reply = {
				.tof_nr_replies = 0,
				.tof_replies = NULL,
			},
		},
	};

	if (!(buf = ctf_proto_stk_encode(mpn_trace_objects, (union msg *)&empty_reply, &sz)))
		return RETVAL_FAILURE;
	/* This is an awkward enough pattern that the API should change. */
	cur_buf = buf;
	cur_sz = sz;
retry_send:
	fd_wait_writable(fd);
	ret_sz = send(fd, cur_buf, cur_sz, MSG_CONFIRM | MSG_NOSIGNAL);
	if (ret_sz == (ssize_t)cur_sz)
		retval = true;
	else if (!ret_sz && !errno) { /* EOF */
		retval = true;
		goto out_free_buf;
	} else if (!ret_sz && errno != EAGAIN && errno != EWOULDBLOCK)
		goto out_free_buf;
	else if (ret_sz >= 0) {
		cur_buf = &cur_buf[MIN(cur_sz, ret_sz)];
		cur_sz -= MIN(cur_sz, ret_sz);
		(void)!sched_yield();
		goto retry_send;
	}
out_free_buf:
	free(buf);
	return retval;
}

static bool
empty_svc_loop(int fd)
{
	struct { enum relative_agency __agency; } agency = {
		.__agency = relative_agency_we_have,
	};
	bool is_reply_pending = false;
	struct ctf_proto_stk_decode_result *cpsdr;
	uintmax_t loop_ctr = 0;
	enum mini_protocol_num mpn = (enum mini_protocol_num)(-1);

redo_handshake:
	(void)!fd_wait_writable(fd);
	if (handshake_xmit(fd) != RETVAL_SUCCESS)
		return false;
loop:
	++loop_ctr;
	ctf_msg(empty_loop, "entering loop %jd agency = %s\n",
			loop_ctr, relative_agency_string(agency.__agency));
	switch (agency.__agency) {
	case relative_agency_we_have:
	case relative_agency_nobody_has:
		if (!is_reply_pending) {
			ctf_msg(empty_loop, "%s, no pending reply\n",
				relative_agency_string(agency.__agency));
			/* if busy, receiving done errors */
			if (agency.__agency == relative_agency_nobody_has) {
				ctf_msg(empty_loop, "sending tof_done %s\n",
					relative_agency_string(agency.__agency));
				if (send_done(fd) == svc_progress_fail)
					goto out;
				agency.__agency = relative_agency_they_have;
			} else {
				/* This doesn't entirely make sense
				 * within the protocol, but sending an
				 * empty reply in this situation avoids
				 * deadlocking because the other end
				 * gags on tof_done */
				if (!send_empty_reply(fd))
					goto out;
				agency.__agency = relative_agency_they_have;
			}
		} else /* is_reply_pending == true */ {
			ctf_msg(empty_loop, "%s, reply pending, "
					"sending empty reply\n",
				relative_agency_string(agency.__agency));
			is_reply_pending = false;
			if (!send_empty_reply(fd))
				goto out;
			agency.__agency = relative_agency_they_have;
		}
		goto loop;
	case relative_agency_they_have:
		struct tof_msg *tof;

		ctf_msg(empty_loop, "remote agency, doing recv()\n");
		(void)!fd_wait_readable(fd);
		if (!(cpsdr = recv_tof(fd))) {
			ctf_msg(empty_loop, "recv_tof() failed\n");
			goto out;
		}
		if (cpsdr->load_result.error.code != CBOR_ERR_NONE) {
			ctf_msg(empty_loop, "got error!\n");
			goto out;
		}
		mpn = cpsdr->sdu.sdu_proto_un.sdu_proto_num;
		if (mpn != mpn_trace_objects) {
			struct handshake *handshake
				= &cpsdr->proto_stk_decode_result_body->handshake_msg;
			if (mpn == mpn_handshake) {
				if (!handshake)
					ctf_msg(empty_loop, "NULL handshake?\n");
				else
					ctf_msg(empty_loop, "unexpected handshake type %s\n",
						handshake_string(handshake->handshake_type));
				goto redo_handshake;
			}
			if (MPN_VALID(mpn))
				ctf_msg(empty_loop, "sdu_proto_num = %s\n",
					mini_protocol_string(mpn));
			else
				ctf_msg(empty_loop, "sdu_proto_num = %d\n",
					(int)mpn);
			goto release_cpsdr;
		}
		tof = &cpsdr->proto_stk_decode_result_body->tof_msg;
		if (tof->tof_msg_type == tof_done)
			agency.__agency = relative_agency_nobody_has;
		else if (tof->tof_msg_type == tof_request) {
			is_reply_pending = true;
			agency.__agency = relative_agency_we_have;
			if (tof->tof_msg_body.request.tof_blocking)
				ctf_msg(empty_loop,
					"error! blocking request!\n");
		}
		tof_free(tof);
	release_cpsdr:
		g_rc_box_release(cpsdr);
		cpsdr = NULL;
		goto loop;
	default:
		mpn = (enum mini_protocol_num)(-1);
		ctf_msg(empty_loop, "unrecognized agency %d, polling\n",
				(int)agency.__agency);
		(void)!fd_wait_readable(fd);
		/* it's unclear what to set the agency to, if anything */
		agency.__agency = relative_agency_they_have;
		/* just go back and retry */
		goto loop;
	}
out:
	return true;
}
