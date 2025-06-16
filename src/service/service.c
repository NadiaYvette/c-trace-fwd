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
	nr_ready = poll(pollfds, state->nr_clients + 2, 0);
	if (nr_ready < 0) {
		ctf_msg(service, "poll() failed\n");
		goto exit_free_pollfds;
	}
	for (k = 0; k < state->nr_clients + 2; ++k) {
		if (!pollfds[k].revents)
			continue;
		else if (pollfds[k].fd == state->ux_sock_fd) {
			if (service_ux_sock(state)) {
				ctf_msg(service, "service_ux_sock() failed\n");
				goto exit_free_pollfds;
			}
		} else if (pollfds[k].fd == state->unix_sock_fd) {
			if (service_unix_sock(state)) {
				ctf_msg(service, "service_unix_sock() failed\n");
				goto exit_free_pollfds;
			}
		} else if (service_client_sock(state, &pollfds[k])) {
			switch (errno) {
			case EINTR:
			case ERESTART:
			case EWOULDBLOCK:
				/* transient error; continue */
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
				service_client_destroy(state, pollfds[k].fd);
				errno = 0;
				break;
			default:
				ctf_msg(service, "service_client_sock() failed\n");
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
	unsigned failure_count = 0;
	int retval;

	(void)!conf;
	ctf_msg(service, "entered service_loop()\n");
	for (;;) {
		if (pthread_mutex_lock(&state->state_lock)) {
			retval = RETVAL_FAILURE;
			break;
		}
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
			++failure_count;
			if (failure_count > 10) {
				ctf_msg(service, "too many failures, exiting\n");
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
