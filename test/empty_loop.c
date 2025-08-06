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

static int
send_tof(struct tof_msg *tof, int fd)
{
	int retval = RETVAL_FAILURE;
	unsigned char *buf, *cur_buf;
	size_t sz, cur_sz;
	ssize_t ret_sz;

	if (!(buf = ctf_proto_stk_encode(tof, &sz)))
		return RETVAL_FAILURE;
	/* This is an awkward enough pattern that the API should change. */
	cur_buf = buf;
	cur_sz = sz;
retry_send:
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
				.tof_blocking = 0,
				.tof_nr_obj   = 0,
			},
		},
	};
	if (send_tof(&done_msg, fd) != RETVAL_SUCCESS) {
		ctf_msg(unix, "service_send_tof() failed\n");
		return svc_progress_fail;
	}
	return svc_progress_send;
}

struct ctf_proto_stk_decode_result *
recv_tof(int fd)
{
	struct ctf_proto_stk_decode_result *cpsdr = NULL;
	char *buf, *cur_buf;
	size_t sz, cur_sz;
	ssize_t ret_sz;

	if (!(buf = calloc(64, 1024))) {
		ctf_msg(empty_loop, "calloc() failed\n");
		return NULL;
	}
	sz = 64 * 1024;
	cur_buf = buf;
	cur_sz = sz;
retry_read:
	if ((ret_sz = recv(fd, cur_buf, cur_sz, 0)) == cur_sz) {
		if (!(cpsdr = ctf_proto_stk_decode(buf)))
			ctf_msg(empty_loop, "ctf_proto_stk_decode() failed\n");
	} else if (!ret_sz) {
		if (!errno) { /* all ready data consumed */
			if (!(cpsdr = ctf_proto_stk_decode(buf)))
				ctf_msg(empty_loop, "ctf_proto_stk_decode() failed\n");
		} else if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto retry_read;
	} else if (ret_sz > 0) {
		cur_buf = &cur_buf[MIN(cur_sz, ret_sz)];
		cur_sz -= MIN(cur_sz, ret_sz);
		(void)!sched_yield();
		goto retry_read;
	}
/* out_free_buf: */
	free(buf);
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

	if (!(buf = ctf_proto_stk_encode(&empty_reply, &sz)))
		return RETVAL_FAILURE;
	/* This is an awkward enough pattern that the API should change. */
	cur_buf = buf;
	cur_sz = sz;
retry_send:
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
	struct { enum agency agency; } agency = { .agency = agency_local, };
	bool is_reply_pending = false;
	struct ctf_proto_stk_decode_result *cpsdr;
	uintmax_t loop_ctr = 0;

redo_handshake:
	if (handshake_xmit(fd) != RETVAL_SUCCESS)
		return false;
loop:
	++loop_ctr;
	ctf_msg(empty_loop, "entering loop %jd agency = %s\n",
			loop_ctr, agency_string(agency.agency));
	switch (agency.agency) {
	case agency_local:
	case agency_nobody:
		if (!is_reply_pending) {
			ctf_msg(empty_loop, "%s, no pending reply, "
					"sending tof_done\n",
					agency_string(agency.agency));
			if (send_done(fd) == svc_progress_fail)
				goto out;
		} else {
			ctf_msg(empty_loop, "%s, reply pending, "
					"sending empty reply\n",
					agency_string(agency.agency));
			is_reply_pending = false;
			if (!send_empty_reply(fd))
				goto out;
		}
		ctf_set_agency(empty_loop, &agency, agency_remote);
		goto loop;
	case agency_remote:
		struct tof_msg *tof;
		enum mini_protocol_num mpn;

		ctf_msg(empty_loop, "remote agency, doing recv()\n");
		if (!(cpsdr = recv_tof(fd))) {
			ctf_msg(empty_loop, "recv_tof() failed\n");
			goto out;
		}
		mpn = cpsdr->sdu.sdu_proto_un.sdu_proto_num;
		if (mpn != mpn_trace_objects) {
			struct handshake *handshake
				= cpsdr->proto_stk_decode_result_body.handshake_msg;
			if (mpn == mpn_handshake) {
				ctf_msg("unexpected handshake type %s\n",
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
		tof = cpsdr->proto_stk_decode_result_body.tof_msg;
		if (tof->tof_msg_type == tof_done)
			ctf_set_agency(empty_loop, &agency, agency_nobody);
		else if (tof->tof_msg_type == tof_request) {
			is_reply_pending = true;
			ctf_set_agency(empty_loop, &agency, agency_local);
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
		struct pollfd pollfd = {
			.fd = fd,
			.events = POLLIN,
			.revents = 0,
		};

		ctf_msg(empty_loop, "unrecognized agency, polling\n");
		if (poll(&pollfd, 1, -1) < 0)
			goto out;
		ctf_set_agency(empty_loop, &agency, agency_remote);
		/* just send a reply */
		/* agency = agency_local; */
		break;
	}
out:
	return true;
}
