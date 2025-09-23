#include <cbor.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "handshake.h"
#include "proto_stk.h"
#include "queue.h"
#include "service.h"
#include "sdu.h"

static int
state_handshake(struct ctf_state *state, struct ctf_conf *conf)
{
	(void)!conf;
	return handshake_xmit(state->unix_io.fd);
}

static bool
setup_queue(struct ctf_state *state, struct ctf_conf *conf)
{
	int fd;

	/* nop returning success w/no preload queue given */
	if (!conf->preload_queue)
		return true;
	if ((fd = open(conf->preload_queue, O_RDONLY)) < 0)
		return false;

	for (;;) {
		unsigned k;
		struct ctf_proto_stk_decode_result *result;
		enum mini_protocol_num mpn;

continue_for_loop:
		if (!(result = ctf_proto_stk_decode(fd))) {
			ctf_msg(state, "decode failed, "
					"ctf_proto_stk_decode() "
					"returned NULL\n");
			continue;
		}
		if (result->load_result.error.code == CBOR_ERR_NOTENOUGHDATA)
			break;
		switch (result->load_result.error.code) {
		case CBOR_ERR_NONE:
			break;
		case CBOR_ERR_NOTENOUGHDATA:
			ctf_msg(state, "got CBOR_ERR_NOTENOUGHDATA, "
					"but continuing until EOF "
					"anyway\n");
			cpsdr_free(result);
			goto continue_for_loop;
		case CBOR_ERR_NODATA:
			ctf_msg(state, "got CBOR_ERR_NODATA, "
					"but continuing until EOF "
					"anyway\n");
			cpsdr_free(result);
			goto continue_for_loop;
		case CBOR_ERR_MALFORMATED:
			ctf_msg(state, "got CBOR_ERR_MALFORMATED, "
					"but continuing until EOF "
					"anyway\n");
			cpsdr_free(result);
			goto continue_for_loop;
		case CBOR_ERR_MEMERROR:
			ctf_msg(state, "got CBOR_ERR_MEMERR, "
					"but continuing until EOF "
					"anyway\n");
			cpsdr_free(result);
			goto continue_for_loop;
		case CBOR_ERR_SYNTAXERROR:
			ctf_msg(state, "got CBOR_ERR_SYNTAXERR, "
					"but continuing until EOF "
					"anyway\n");
			cpsdr_free(result);
			goto continue_for_loop;
		default:
			ctf_msg(state, "got unknown error %d, "
					"but continuing until EOF "
					"anyway\n",
					result->load_result.error.code);
			cpsdr_free(result);
			goto continue_for_loop;
		}
		switch (mpn = result->sdu.sdu_proto_un.sdu_proto_num) {
		case mpn_handshake:
		case mpn_EKG_metrics:
		case mpn_data_points:
			break;
		case mpn_trace_objects:
			struct tof_msg *tof_msg;

			tof_msg = &result->proto_stk_decode_result_body->tof_msg;
			switch (tof_msg->tof_msg_type) {
			case tof_request:
			case tof_done:
				tof_free(&result->proto_stk_decode_result_body->tof_msg);
				cpsdr_free(result);
				continue;
			case tof_reply:
				for (k = 0; k < tof_msg->tof_msg_body.reply.tof_nr_replies; ++k) {
					if (to_enqueue(&state->unix_io.in_queue, tof_msg->tof_msg_body.reply.tof_replies[k]) == RETVAL_SUCCESS)
						continue;
					ctf_msg(state, "enqueue failed\n");
					tof_free(&result->proto_stk_decode_result_body->tof_msg);
					cpsdr_free(result);
					goto out_close_fd;
				}
				break;
			default:
				ctf_msg(state,
					"unrecognized tof_msg_type %d\n",
					(int)tof_msg->tof_msg_type);
				break;
			}
			break;
		default:
			ctf_msg(state, "skipping trace object for "
					"protocol %s\n",
					mini_protocol_string(mpn));
			if (!!result->proto_stk_decode_result_body) {

				ctf_msg(state, "->proto_stk_decode_result_body %p not NULL? should we cbor_decref() it?\n", result->proto_stk_decode_result_body);
				if (result->load_result.error.code != CBOR_ERR_NONE)
					ctf_msg(state, "load result error code =%d != CBOR_ERR_NONE, not decref'ing\n", result->load_result.error.code);
				else if (!!result->proto_stk_decode_result_body->undecoded) {
					ctf_msg(state, "load result error code == CBOR_ERR_NONE, ->undecoded != NULL, decref'ing %p now\n", &result->proto_stk_decode_result_body->undecoded);
					ctf_cbor_decref(state, &result->proto_stk_decode_result_body->undecoded);
				} else
					ctf_msg(state, "load result error code == CBOR_ERR_NONE, ->undecoded == NULL, doing nothing\n");
			}
			cpsdr_free(result);
			continue;
		}
	}
	close(fd);
	return true;
out_close_fd:
	close(fd);
	return false;
}

static bool
setup_unix_sock(int *fd, struct sockaddr *sockaddr)
{
	*fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (*fd < 0) {
		ctf_msg(state, "socket creation for Unix sock failed\n");
		return false;
	}
	if (connect(*fd, sockaddr, sizeof(struct sockaddr_un))) {
		struct sockaddr_un *sa_un = (struct sockaddr_un *)sockaddr;

		ctf_msg(state, "connect() to Unix sock failed\n");
		ctf_msg(state, "Unix sock path = \"%s\"\n",
				sa_un->sun_path);
		ctf_msg(state, "errno = %d, errmsg = \"%s\"\n", errno,
				strerror(errno));
		return false;
	}
	return true;
}

/* This may be worth separating the components of for readability's sake. */
int
setup_state(struct ctf_state **state, struct ctf_conf *conf)
{
	pthread_mutexattr_t state_lock_attr;
	struct addrinfo *ux_addr;
	struct sockaddr *unix_sock;
	struct timeval timeval;
	socklen_t ai_addrlen;
	int ai_family, ai_socktype, ai_protocol, page_size,
		retval = RETVAL_FAILURE;

	if (!(*state = g_rc_box_new0(struct ctf_state))) {
		ctf_msg(state, "g_rc_box_new0() failed\n");
		return RETVAL_FAILURE;
	}
	if (pthread_mutexattr_init(&state_lock_attr)) {
		ctf_msg(state, "pthread_mutexattr_init failed\n");
		goto exit_failure;
	}
	(void)!pthread_mutex_init(&(*state)->state_lock, &state_lock_attr);
	unix_sock = (struct sockaddr *)&conf->unix_sock;
	if (!setup_unix_sock(&(*state)->unix_io.fd, unix_sock)) {
		ctf_msg(state, "setup_unix_sock() failed\n");
		goto exit_destroy_mutex;
	}
	io_queue_init(&(*state)->unix_io, (*state)->unix_io.fd);
	FD_SET((*state)->unix_io.fd, &(*state)->state_fds);
	page_size = getpagesize();
	if (page_size < 0) {
		ctf_msg(state, "page size detection failed\n");
		goto exit_shutdown_unix;
	}
	ux_addr = conf->ux_addr;
	ai_family = ux_addr->ai_family;
	ai_socktype = ux_addr->ai_socktype;
	ai_protocol = ux_addr->ai_protocol;
	ai_addrlen = ux_addr->ai_addrlen;
	(*state)->ux_sock_fd = socket(ai_family, ai_socktype, ai_protocol);
	if ((*state)->ux_sock_fd == -1) {
		ctf_msg(state, "socket creation for ux failed\n");
		goto exit_shutdown_unix;
	}
	FD_SET((*state)->ux_sock_fd, &(*state)->state_fds);
	if (bind((*state)->ux_sock_fd, ux_addr->ai_addr, ai_addrlen)) {
		ctf_msg(state, "bind() ux socket failed\n");
		goto exit_shutdown_ux;
	}
	if (listen((*state)->ux_sock_fd, 64)) {
		ctf_msg(state, "listen() ux socket failed\n");
		goto exit_shutdown_ux;
	}
	timeval.tv_sec = 0;
	timeval.tv_usec = 10 * 1000; /* 10 ms */
	if (setsockopt((*state)->ux_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeval, sizeof(struct timeval))) {
		ctf_msg(state, "setsockopt() ux socket failed\n");
		goto exit_shutdown_ux;
	}
	if (!setup_queue(*state, conf))
		goto exit_shutdown_ux;
	retval = state_handshake(*state, conf);
	/* (*state)->agency = agency_local; */
	ctf_set_agency(state, &(*state)->unix_io, agency_local);
	ctf_msg(state, "state_handshake() returned %d\n", retval);
	return retval;
exit_shutdown_ux:
	(void)!shutdown((*state)->ux_sock_fd, SHUT_RDWR);
	(void)!close((*state)->ux_sock_fd);
	(*state)->ux_sock_fd = 0;
exit_shutdown_unix:
	(void)!shutdown((*state)->unix_io.fd, SHUT_RDWR);
	(void)!close((*state)->unix_io.fd);
	(*state)->unix_io.fd = 0;
exit_destroy_mutex:
	(void)!pthread_mutex_destroy(&(*state)->state_lock);
	(void)!pthread_mutexattr_destroy(&state_lock_attr);
exit_failure:
	g_rc_box_release(*state);
	*state = NULL;
	return retval;
}

static void
state_release_memory(void *p)
{
	struct ctf_state *state = p;

	(void)!shutdown(state->unix_io.fd, SHUT_RDWR);
	(void)!close(state->unix_io.fd);
	state->unix_io.fd = -1;
	(void)!shutdown(state->ux_sock_fd, SHUT_RDWR);
	state->ux_sock_fd = -1;
	(void)!pthread_mutex_destroy(&state->state_lock);
	free(state->ux_io);
}

void teardown_state(struct ctf_state **state)
{
	g_rc_box_release_full(*state, state_release_memory);
	*state = NULL;
}
