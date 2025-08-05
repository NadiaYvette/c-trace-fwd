#include <getopt.h>
#include <glib.h>
#include <inttypes.h>
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

struct ctf_proto_stk_decode_result *
recv_tof(int fd)
{
	struct ctf_proto_stk_decode_result *cpsdr = NULL;
	char *buf, *cur_buf;
	size_t sz, cur_sz;
	ssize_t ret_sz;

	if (!(buf = calloc(64, 1024)))
		return NULL;
	sz = 64 * 1024;
	cur_buf = buf;
	cur_sz = sz;
retry_read:
	if ((ret_sz = recv(fd, cur_buf, cur_sz, MSG_DONTWAIT)) == cur_sz)
		cpsdr = ctf_proto_stk_decode(buf);
	else if (!ret_sz) {
		if (!errno) /* all ready data consumed */
			cpsdr = ctf_proto_stk_decode(buf);
		else if (errno == EAGAIN || errno == EWOULDBLOCK)
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
	enum agency agency = agency_remote;
	struct ctf_proto_stk_decode_result *cpsdr;

	if (handshake_xmit(fd) != RETVAL_SUCCESS)
		return false;
loop:
	switch (agency) {
	case agency_local:
		break;
	case agency_remote:
		struct tof_msg *tof;
		bool reply_success = true;

		if (!(cpsdr = recv_tof(fd))) {
			ctf_msg(empty_loop, "recv_tof() failed\n");
			goto out;
		}
		if (cpsdr->sdu.sdu_proto_un.sdu_proto_num != mpn_trace_objects)
			goto release_cpsdr;
		tof = cpsdr->proto_stk_decode_result_body.tof_msg;
		if (tof->tof_msg_type == tof_request)
			reply_success = send_empty_reply(fd);
		tof_free(tof);
	release_cpsdr:
		g_rc_box_release(cpsdr);
		cpsdr = NULL;
		if (reply_success)
			goto loop;
		else
			goto out;
	case agency_nobody:
		break;
	default:
		/* just send a reply */
		agency = agency_local;
		break;
	}
out:
	return true;
}
