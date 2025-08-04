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

const char *
agency_string(enum agency agency)
{
	static const char *agency_table[] = {
		[agency_local]  = "agency_local",
		[agency_nobody] = "agency_nobody",
		[agency_remote] = "agency_remote",
	};

	if (AGENCY_VALID(agency))
		return agency_table[agency];
	return NULL;
}

static struct handshake_propose_version_pair handshake_versions[] = {
	[0] = {
		.propose_version_key = 1, /* 19, */
		.propose_version_value = NULL
	}
};

static struct handshake handshake_proposal = {
	.handshake_type = handshake_propose_versions,
	.handshake_message = {
		.propose_versions = {
			.handshake_propose_versions_len = 1,
			.handshake_propose_versions = handshake_versions
		}
	}
};

static cbor_item_t *handshake_proposal_cbor = NULL;

static void
sig_action(int sig, siginfo_t *info, void *data)
{
	(void)!info;
	(void)!data;
	ctf_msg(state, "received signal %d\n", sig);
}

static int
state_handshake(struct c_trace_fwd_state *state, struct c_trace_fwd_conf *conf)
{
	struct handshake *handshake_reply;
	cbor_item_t *reply_cbor, *handshake_proposal_map;
	unsigned char *sdu_buf, *buf = NULL;
	size_t buf_sz, sdu_buf_sz;
	ssize_t reply_len;
	int retval = RETVAL_FAILURE, flg = MSG_CONFIRM | MSG_NOSIGNAL;
	struct sigaction old_sigact, new_sigact;
	struct sdu sdu, reply_sdu;
	struct cbor_load_result cbor_load_result;
	union sdu_ptr sdu_ptr;
	sigset_t sig_mask, old_sig_mask;

	ctf_msg(state, "entering\n");
	ctf_msg(state, "different message\n");
	handshake_versions[0].propose_version_key = 1;
	if (!handshake_versions[0].propose_version_value) {
		handshake_versions[0].propose_version_value
			= cbor_build_uint32( 764824073 /* 19 */ );
		if (!handshake_versions[0].propose_version_value) {
			ctf_msg(state, "version value alloc failed\n");
			return RETVAL_FAILURE;
		}
	}
	ctf_msg(state, "past checking version value, about to cbor encode\n");
	if (!(handshake_proposal_cbor = handshake_encode(&handshake_proposal))) {
		ctf_msg(state, "handshake_encode() returned NULL & failed!\n");
		return RETVAL_FAILURE;
	}
	ctf_msg(state, "handshake_encode() succeeded\n");
	cbor_describe(handshake_proposal_cbor, stderr);
	if (!cbor_serialize_alloc(handshake_proposal_cbor, &buf, &buf_sz)) {
		ctf_msg(state, "cbor_serialize_alloc failed\n");
		return RETVAL_FAILURE;
	}
	if (cbor_typeof(handshake_proposal_cbor) != CBOR_TYPE_ARRAY) {
		ctf_msg(state, "handshake_encode() didn't return array!\n");
		return RETVAL_FAILURE;
	}
	if (cbor_array_size(handshake_proposal_cbor) != 2) {
		ctf_msg(state, "handshake_encode() returned wrong size array!\n");
		return RETVAL_FAILURE;
	}
	if (!(handshake_proposal_map = cbor_array_get(handshake_proposal_cbor, 1))) {
		ctf_msg(state, "handshake_encode() lacked [1] array entry!\n");
		return RETVAL_FAILURE;

	}
	if (cbor_typeof(handshake_proposal_map) != CBOR_TYPE_MAP) {
		ctf_msg(state, "handshake_encode() [1] array entry not CBOR_TYPE_MAP!\n");
		return RETVAL_FAILURE;
	}
	sdu_buf_sz = buf_sz + 2*sizeof(uint32_t);
	if (!(sdu_buf = calloc(sdu_buf_sz, sizeof(unsigned char)))) {
		ctf_msg(state, "sdu_buf calloc failed\n");
		goto out_free_buf;
	}
	sdu.sdu_xmit = (uint32_t)time(NULL);
	sdu.sdu_init_or_resp = false;
	sdu.sdu_proto_un.sdu_proto_word16 = 19;
	sdu.sdu_len = buf_sz;
	sdu.sdu_data = (char *)&sdu_buf[sizeof(struct sdu)];
	memcpy(&sdu_buf[2*sizeof(uint32_t)], buf, buf_sz);
	sdu_ptr.sdu8 = (uint8_t *)sdu_buf;
	if (sdu_encode(&sdu, sdu_ptr) != RETVAL_SUCCESS) {
		ctf_msg(state, "sdu_encode failed\n");
		goto out_free_sdu;
	}
	if (send(state->unix_io.fd, sdu_buf, buf_sz + 2*sizeof(uint32_t), flg) <= 0 && errno != 0) {
		ctf_msg(state, "write error in handshake\n");
		goto out_free_buf;
	}
	if (buf_sz < 64 * 1024) {
		unsigned char *new_buf;

		ctf_msg(state, "reallocating buffer\n");
		if (!(new_buf = realloc(buf, 64 * 1024)))
			goto out_free_buf;
		buf_sz = 64 * 1024;
		buf = new_buf;
		ctf_msg(state, "buffer successfully reallocated\n");
	}
	ctf_msg(state, "about to try to read for handshake reply\n");
	sigemptyset(&sig_mask);
	sigemptyset(&old_sig_mask);
	sigaddset(&sig_mask, SIGALRM);
	sigaddset(&sig_mask, SIGPIPE);
	if (!!sigprocmask(SIG_BLOCK, &sig_mask, &old_sig_mask))
		ctf_msg(state, "sigprocmask failed\n");
	sigaddset(&old_sig_mask, SIGPIPE);
	new_sigact.sa_sigaction = sig_action;
	sigemptyset(&new_sigact.sa_mask);
	sigaddset(&new_sigact.sa_mask, SIGALRM);
	sigaddset(&new_sigact.sa_mask, SIGPIPE);
	new_sigact.sa_flags = SA_SIGINFO;
	new_sigact.sa_restorer = NULL;
	if (!!sigaction(SIGALRM, &new_sigact, &old_sigact))
		ctf_msg(state, "sigaction failed\n");
	/* The alarm is to interrupt stalled reads to restart them. */
	alarm(1);
	sigdelset(&sig_mask, SIGPIPE);
	if (!!sigprocmask(SIG_UNBLOCK, &sig_mask, &old_sig_mask))
		ctf_msg(state, "sigprocmask failed\n");
	while ((reply_len = recv(state->unix_io.fd, buf, buf_sz, 0)) <= 0) {
		/* Cancel any pending alarms. */
		alarm(0);
		if (!!errno && errno != EAGAIN && errno != EINTR && errno != EWOULDBLOCK) {
			ctf_msg(state, "handshake read got errno %d\n", errno);
			break;
		}
		errno = 0;
		ctf_msg(state, "read zero data, looping\n");
		sleep(1);
		alarm(1);
	}
	alarm(0);
	sigaddset(&sig_mask, SIGPIPE);
	if (!!sigprocmask(SIG_BLOCK, &sig_mask, &old_sig_mask))
		ctf_msg(state, "sigprocmask failed\n");
	if (!!sigaction(SIGALRM, &old_sigact, NULL))
		ctf_msg(state, "sigaction cleanup failed\n");
	if (!errno)
		ctf_msg(state, "got past reading for handshake reply\n");
	else
		ctf_msg(state, "error reading for handshake reply\n");
	if (reply_len < 0) {
		ctf_msg(state, "negative reply length, exiting\n");
		goto out_free_buf;
	}
	ctf_msg(state, "attempting sdu_decode()\n");
	sdu_ptr.sdu8 = (uint8_t *)buf;
	if (sdu_decode(sdu_ptr, &reply_sdu) != RETVAL_SUCCESS) {
		ctf_msg(state, "saw sdu_decode() failure, now goto "
				"out_free_buf\n");
		goto out_free_buf;
	}
	ctf_msg(state, "got past sdu_decode(), checking reply_sdu.sdu_len\n");
	if (reply_sdu.sdu_len != reply_len - 2 * sizeof(uint32_t)) {
		ctf_msg(state, "SDU length unexpected was 0x%x expected"
			       " 0x%zx\n", reply_sdu.sdu_len,
			       (size_t)reply_len);
		reply_sdu.sdu_len = reply_len - 2*sizeof(uint32_t);
	}
	ctf_msg(state, "got past reply_sdu.sdu_len check trying cbor_load()\n");
	if (!(reply_cbor = cbor_load(&buf[2*sizeof(uint32_t)], reply_sdu.sdu_len, &cbor_load_result))) {
		ctf_msg(state, "cbor_load() failed, freeing buffer\n");
		goto out_free_buf;
	}
	ctf_msg(state, "got past cbor_load(), checking result\n");
	switch (cbor_load_result.error.code) {
	case CBOR_ERR_NONE:
		ctf_msg(state, "got CBOR_ERR_NONE, continuing\n");
		break;
	case CBOR_ERR_NOTENOUGHDATA:
		ctf_msg(state, "got CBOR_ERR_NOTENOUGHDATA\n");
		goto out_decref_reply;
		break;
	case CBOR_ERR_NODATA:
		ctf_msg(state, "got CBOR_ERR_NOTENOUGHDATA\n");
		goto out_decref_reply;
		break;
	case CBOR_ERR_MALFORMATED:
		ctf_msg(state, "got CBOR_ERR_NOTENOUGHDATA\n");
		goto out_decref_reply;
		break;
	case CBOR_ERR_MEMERROR:
		ctf_msg(state, "got CBOR_ERR_NOTENOUGHDATA\n");
		goto out_decref_reply;
		break;
	case CBOR_ERR_SYNTAXERROR:
		ctf_msg(state, "got CBOR_ERR_NOTENOUGHDATA\n");
		goto out_decref_reply;
		break;
	default:
		ctf_msg(state, "got unrecognized CBOR error code\n");
		goto out_decref_reply;
		break;
	}
	ctf_msg(state, "got past checking cbor_load() result, "
		       "doing handshake_decode()\n");
	if (!(handshake_reply = handshake_decode(reply_cbor))) {
		ctf_msg(state, "handshake_decode() failed decref(&reply_cbor)\n");
		goto out_decref_reply;
	}
	ctf_msg(state, "got past handshake_decode(), checking reply type\n");
	if (handshake_reply->handshake_type != handshake_accept_version) {
		ctf_msg(state, "reply type not acceptance, decref(&reply_cbor)\n");
		goto out_handshake_free;
	}
	ctf_msg(state, "state_handshake() succeeded, returning RETVAL_SUCCESS\n");
	retval = RETVAL_SUCCESS;
out_handshake_free:
	handshake_free(handshake_reply);
out_decref_reply:
	if (!!retval)
		ctf_msg(state, "out_decref_reply: label of state_handshake()\n");
	ctf_cbor_decref(state, &reply_cbor);
out_free_sdu:
	if (!!retval)
		ctf_msg(state, "out_free_sdu: label of state_handshake()\n");
	free(sdu_buf);
out_free_buf:
	if (!!retval)
		ctf_msg(state, "out_free_buf: label of state_handshake()\n");
	free(buf);
	return retval;
}

static bool
setup_queue(struct c_trace_fwd_state *state, struct c_trace_fwd_conf *conf)
{
	int fd;
	char *buf;

	/* nop returning success w/no preload queue given */
	if (!conf->preload_queue)
		return true;
	if ((fd = open(conf->preload_queue, O_RDONLY)) < 0)
		return false;
	if (!(buf = calloc(64, 1024)))
		goto out_close_fd;

	for (;;) {
		int ret;
		unsigned k;
		struct sdu sdu;
		union sdu_ptr sdu_ptr;
		struct ctf_proto_stk_decode_result *result;
		enum mini_protocol_num mpn;

continue_for_loop:
		if ((ret = read(fd, buf, 8)) < 0) {
			ctf_msg(state, "read() failed\n");
			goto out_free_buf;
		}
		if (!ret) /* EOF */
			goto out_exit_for_loop;
		sdu_ptr.sdu8 = (uint8_t *)buf;
		if (sdu_decode(sdu_ptr, &sdu) != RETVAL_SUCCESS) {
			ctf_msg(state, "sdu decode failed\n");
			goto out_free_buf;
		}
		if ((ret = read(fd, &buf[8], sdu.sdu_len)) != sdu.sdu_len) {
			ctf_msg(state, "read() failed\n");
			/* gracefully ignore truncated captures at EOF */
			if (!ret)
				break;
			else
				goto out_free_buf;
		}
		if (!(result = ctf_proto_stk_decode(buf))) {
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
		mpn = result->sdu.sdu_proto_un.sdu_proto_num;
		if (mpn != mpn_trace_objects) {
			ctf_msg(state, "skipping trace object for "
					"protocol %s\n",
					mini_protocol_string(mpn));
			if (!!result->proto_stk_decode_result_body.undecoded) {

				ctf_msg(state, "undecoded %p not NULL? should we cbor_decref() it?\n", result->proto_stk_decode_result_body.undecoded);
				if (result->load_result.error.code != CBOR_ERR_NONE)
					ctf_msg(state, "load result error code =%d != CBOR_ERR_NONE, not decref'ing\n", result->load_result.error.code);
				else {
					ctf_msg(state, "load result error code == CBOR_ERR_NONE, decref'ing it now\n");
					ctf_cbor_decref(state, &result->proto_stk_decode_result_body.undecoded);
				}
			}
			cpsdr_free(result);
			continue;
		}
		if (result->proto_stk_decode_result_body.tof_msg->tof_msg_type != tof_reply) {
			tof_free(result->proto_stk_decode_result_body.tof_msg);
			cpsdr_free(result);
			continue;
		}
		for (k = 0; k < result->proto_stk_decode_result_body.tof_msg->tof_msg_body.reply.tof_nr_replies; ++k) {
			if (to_enqueue(&state->unix_io.in_queue, result->proto_stk_decode_result_body.tof_msg->tof_msg_body.reply.tof_replies[k]) == RETVAL_SUCCESS)
				continue;
			ctf_msg(state, "enqueue failed\n");
			tof_free(result->proto_stk_decode_result_body.tof_msg);
			cpsdr_free(result);
			goto out_free_buf;
		}
	}
out_exit_for_loop:
	free(buf);
	close(fd);
	return true;
out_free_buf:
	free(buf);
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
setup_state(struct c_trace_fwd_state **state, struct c_trace_fwd_conf *conf)
{
	pthread_mutexattr_t state_lock_attr;
	struct addrinfo *ux_addr;
	struct sockaddr *unix_sock;
	struct timeval timeval;
	socklen_t ai_addrlen;
	int ai_family, ai_socktype, ai_protocol, page_size,
		retval = RETVAL_FAILURE;

	if (!(*state = g_rc_box_new0(struct c_trace_fwd_state))) {
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
	struct c_trace_fwd_state *state = p;

	(void)!shutdown(state->unix_io.fd, SHUT_RDWR);
	(void)!close(state->unix_io.fd);
	state->unix_io.fd = -1;
	(void)!shutdown(state->ux_sock_fd, SHUT_RDWR);
	state->ux_sock_fd = -1;
	(void)!pthread_mutex_destroy(&state->state_lock);
	free(state->ux_io);
}

void teardown_state(struct c_trace_fwd_state **state)
{
	g_rc_box_release_full(*state, state_release_memory);
	*state = NULL;
}
