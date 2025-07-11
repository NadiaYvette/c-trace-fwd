#include <cbor.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "handshake.h"
#include "proto_stk.h"
#include "sdu.h"

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
	int retval = RETVAL_FAILURE;
	struct sigaction old_sigact, new_sigact;
	struct sdu sdu, reply_sdu;
	struct cbor_load_result cbor_load_result;
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
	if (sdu_encode(&sdu, (uint32_t *)sdu_buf) != RETVAL_SUCCESS) {
		ctf_msg(state, "sdu_encode failed\n");
		goto out_free_sdu;
	}
	if (write(state->unix_sock_fd, sdu_buf, buf_sz + 2*sizeof(uint32_t)) <= 0 && errno != 0) {
		ctf_msg(state, "write error in handshake\n");
		goto out_free_buf;
	}
	if (buf_sz < 1024 * 1024) {
		unsigned char *new_buf;

		ctf_msg(state, "reallocating buffer\n");
		if (!(new_buf = realloc(buf, 1024 * 1024)))
			goto out_free_buf;
		buf_sz = 1024 * 1024;
		buf = new_buf;
		ctf_msg(state, "buffer successfully reallocated\n");
	}
	ctf_msg(state, "about to try to read for handshake reply\n");
	sigemptyset(&sig_mask);
	sigemptyset(&old_sig_mask);
	sigaddset(&sig_mask, SIGALRM);
	if (!!sigprocmask(SIG_BLOCK, &sig_mask, &old_sig_mask))
		ctf_msg(state, "sigprocmask failed\n");
	new_sigact.sa_sigaction = sig_action;
	sigemptyset(&new_sigact.sa_mask);
	sigaddset(&new_sigact.sa_mask, SIGALRM);
	new_sigact.sa_flags = SA_SIGINFO;
	new_sigact.sa_restorer = NULL;
	if (!!sigaction(SIGALRM, &new_sigact, &old_sigact))
		ctf_msg(state, "sigaction failed\n");
	/* The alarm is to interrupt stalled reads to restart them. */
	alarm(1);
	if (!!sigprocmask(SIG_UNBLOCK, &sig_mask, &old_sig_mask))
		ctf_msg(state, "sigprocmask failed\n");
	while ((reply_len = read(state->unix_sock_fd, buf, buf_sz)) <= 0) {
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
	if (sdu_decode((uint32_t *)buf, &reply_sdu) != RETVAL_SUCCESS)
		goto out_free_buf;
	ctf_msg(state, "got past sdu_decode(), checking reply_sdu.sdu_len\n");
	if (reply_sdu.sdu_len != reply_len - 2 * sizeof(uint32_t)) {
		ctf_msg(state, "SDU length unexpected was 0x%x expected %zx\n",
				reply_sdu.sdu_len, (size_t)reply_len);
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
	cbor_decref(&reply_cbor);
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
	socklen_t ai_addrlen;
	int ai_family, ai_socktype, ai_protocol, page_size,
		retval = RETVAL_FAILURE;

	*state = calloc(1, sizeof(struct c_trace_fwd_state));
	if (!*state) {
		ctf_msg(state, "calloc() failed\n");
		return RETVAL_FAILURE;
	}
	if (pthread_mutexattr_init(&state_lock_attr)) {
		ctf_msg(state, "pthread_mutexattr_init failed\n");
		goto exit_failure;
	}
	(void)!pthread_mutex_init(&(*state)->state_lock, &state_lock_attr);
	(*state)->stack = calloc(1024, sizeof(cbor_item_t *));
	if (!(*state)->stack) {
		ctf_msg(state, "state->stack allocation failed\n");
		goto exit_destroy_mutex;
	}
	(*state)->stack_sz = 1024;
	(*state)->stack_top = -1;
	unix_sock = (struct sockaddr *)&conf->unix_sock;
	if (!setup_unix_sock(&(*state)->unix_sock_fd, unix_sock)) {
		ctf_msg(state, "setup_unix_sock() failed\n");
		goto exit_free_stack;
	}
	FD_SET((*state)->unix_sock_fd, &(*state)->state_fds);
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
		ctf_msg(state, "binding ux socket failed\n");
		goto exit_shutdown_ux;
	}
	retval = state_handshake(*state, conf);
	ctf_msg(state, "state_handshake() returned %d\n", retval);
	return retval;
exit_shutdown_ux:
	(void)!shutdown((*state)->ux_sock_fd, SHUT_RDWR);
	(void)!close((*state)->ux_sock_fd);
	(*state)->ux_sock_fd = 0;
exit_shutdown_unix:
	(void)!shutdown((*state)->unix_sock_fd, SHUT_RDWR);
	(void)!close((*state)->unix_sock_fd);
	(*state)->unix_sock_fd = 0;
exit_free_stack:
	free((*state)->stack);
	(*state)->stack_top = -1;
exit_destroy_mutex:
	(void)!pthread_mutex_destroy(&(*state)->state_lock);
	(void)!pthread_mutexattr_destroy(&state_lock_attr);
exit_failure:
	free(*state);
	*state = NULL;
	return retval;
}

void teardown_state(struct c_trace_fwd_state **state)
{
	(void)!shutdown((*state)->unix_sock_fd, SHUT_RDWR);
	(void)!close((*state)->unix_sock_fd);
	(*state)->unix_sock_fd = 0;
	(void)!shutdown((*state)->ux_sock_fd, SHUT_RDWR);
	(void)!close((*state)->ux_sock_fd);
	(*state)->ux_sock_fd = 0;
	(void)!pthread_mutex_destroy(&(*state)->state_lock);
	free(*state);
	*state = NULL;
}
