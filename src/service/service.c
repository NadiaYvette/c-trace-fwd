#include <cbor.h>
#include <cbor/data.h>
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "proto_stk.h"
#include "sdu.h"
#include "service.h"
#include "tof.h"

static struct pollfd *
service_create_pollfds(struct c_trace_fwd_state *state)
{
	int k, m;
	struct pollfd *pollfds;

	pollfds = calloc(state->nr_clients + 2, sizeof(struct pollfd));
	if (!pollfds)
		return NULL;
	for (k = m = 0; k < FD_SETSIZE; ++k) {
		if (!FD_ISSET(k, &state->state_fds))
			continue;
		pollfds[m].fd = k;
		pollfds[m].events = POLLIN|POLLPRI|POLLOUT|POLLERR|POLLHUP;
		++m;
	}
	return pollfds;
}

static bool
service_issue_request(struct c_trace_fwd_state *state)
{
	bool status = true;
	char *buf, *cur_buf;
	size_t sz, cur_sz;
	ssize_t ret;
	struct tof_msg tof_msg = {
		.tof_msg_type = tof_request,
		.tof_msg_body = {
			.request = {
				.tof_blocking = true,
				.tof_nr_obj = 1,
			},
		},
	};
	if (!(buf = ctf_proto_stk_encode(&tof_msg, &sz))) {
		ctf_msg(service, "ctf_proto_stk_encode() failed\n");
		return false;
	}
	cur_buf = buf;
	cur_sz = sz;
restart_write:
	if ((ret = write(state->unix_sock_fd, cur_buf, cur_sz)) == cur_sz)
		goto out_free_buf;
	if (ret < 0) {
		ctf_msg(service, "write() failed, errno = %d\n", errno);
		status = false;
	} else {
		cur_buf = &cur_buf[ret];
		cur_sz -= ret;
		ctf_msg(service, "wrote %zd, looping to write another "
				"%zu, errno = %d\n",
				ret, cur_sz, errno);
		errno = 0;
		goto restart_write;
	}
out_free_buf:
	free(buf);
	return status;
}

static int
service_loop_core(struct c_trace_fwd_state *state)
{
	int nr_ready, k, retval = RETVAL_FAILURE;
	struct pollfd *pollfds;

	ctf_msg(service, "entered service_loop_core()\n");
	if (!(pollfds = service_create_pollfds(state))) {
		ctf_msg(service, "service_create_pollfds() failed\n");
		return RETVAL_FAILURE;
	}
	ctf_msg(service, "service_loop_core() about to poll()\n");
	nr_ready = poll(pollfds, state->nr_clients + 2, 0);
	if (nr_ready < 0) {
		ctf_msg(service, "poll() failed\n");
		goto exit_free_pollfds;
	}
	if (!nr_ready) {
		ctf_msg(service, "poll() returned zero ready fds\n");
		goto exit_free_pollfds;
	}
	for (k = 0; k < state->nr_clients + 2; ++k) {
		if (!pollfds[k].revents)
			continue;
		else if (pollfds[k].fd == state->ux_sock_fd) {
			ctf_msg(service, "ux_sock_fd ready\n");
			if (service_ux_sock(state)) {
				ctf_msg(service, "service_ux_sock() failed\n");
				goto exit_free_pollfds;
			}
		} else if (pollfds[k].fd == state->unix_sock_fd) {
			ctf_msg(service, "unix_sock_fd ready\n");
			if (service_unix_sock(state) != RETVAL_SUCCESS) {
				ctf_msg(service, "service_unix_sock() "
						"failed, continuing\n");
				ctf_msg(service, "need to reconnect or "
						"otherwise propagate "
						"the error upward()\n");
				continue;
			}
			if (!!(pollfds[k].revents & POLLHUP)) {
				ctf_msg(service, "big trouble! lost "
						"upstream socket "
						"connection!\n");
				goto exit_free_pollfds;
			}
		} else if (service_client_sock(state, &pollfds[k])) {
			ctf_msg(service, "other socket (TCP?) ready\n");
			switch (errno) {
			case EINTR:
			case ERESTART:
			case EWOULDBLOCK:
				/* transient error; continue */
				ctf_msg(service, "transient network "
						"error\n");
				errno = 0;
				break;
			case ECOMM:
			case ECONNABORTED:
			case ECONNREFUSED:
			case ECONNRESET:
			case EHOSTDOWN:
			case EHOSTUNREACH:
			case EINPROGRESS:
			case EISCONN:
			case ENETDOWN:
			case ENETUNREACH:
			case ENOTUNIQ:
			case EPROTO:
			case EPROTONOSUPPORT:
			case EPROTOTYPE:
			case EREMCHG:
			case ERFKILL:
			case ESHUTDOWN:
			case ESOCKTNOSUPPORT:
				/*
				 * Some kind of unrecoverable network
				 * error has happened, so close the
				 * connection, update state, reset errno.
				 */
				ctf_msg(service, "unrecoverable network "
						"error\n");
				service_client_destroy(state, pollfds[k].fd);
				errno = 0;
				break;
			default:
				ctf_msg(service, "service_client_sock() "
						"failed errno = %d\n", errno);
				goto exit_free_pollfds;
			}
		} else {
			ctf_msg(service, "fell through if chain, unclear\n");
		}
	}
	ctf_msg(service, "got past for () loop in service_loop_core()\n");
	retval = RETVAL_SUCCESS;
exit_free_pollfds:
	free(pollfds);
	return retval;
}

int
service_loop(struct c_trace_fwd_state *state, struct c_trace_fwd_conf *conf)
{
	unsigned failure_count = 64;
	bool status;
	int retval;

	(void)!conf;
	ctf_msg(service, "entered service_loop()\n");
	for (;;) {
		/* The request-issuing half of the service loop.
		 * We always keep requests in flight.
		 */
		if (pthread_mutex_lock(&state->state_lock)) {
			retval = RETVAL_FAILURE;
			break;
		}
		ctf_msg(service, "about to service_issue_request()\n");
		status = service_issue_request(state);
		(void)!pthread_mutex_unlock(&state->state_lock);
		if (!status) {
			ctf_msg(service, "service_issue_request() failed\n");
			if (!--failure_count) {
				ctf_msg(service, "too many failures, "
						"exiting\n");
				break;
			}
		}

		/* The reply-awaiting half of the service loop. */
		if (pthread_mutex_lock(&state->state_lock)) {
			retval = RETVAL_FAILURE;
			break;
		}
		ctf_msg(service, "about to service_loop_core()\n");
		retval = service_loop_core(state);
		/*
		 * This is to give other threads a chance to acquire the
		 * lock. In principle, if there were a way to check for
		 * pending acquisitions in the pthread API, dropping the
		 * lock could be avoided, though narrowing the scope
		 * where the lock is being held and servicing different
		 * file descriptors in different threads might be a more
		 * immediate concern after decoding is verified.
		 */
		(void)!pthread_mutex_unlock(&state->state_lock);
		if (retval != RETVAL_SUCCESS) {
			ctf_msg(service, "service_loop_core() failed\n");
			if (!--failure_count) {
				ctf_msg(service, "too many failures, "
						"exiting\n");
				break;
			}
		}
		(void)!sched_yield();
	}
	ctf_msg(service, "fell out of service_loop()\n");
	/*
	 * Always abnormally terminating is a sign that some sort of
	 * control interface is needed.
	 */
	return retval;
}
