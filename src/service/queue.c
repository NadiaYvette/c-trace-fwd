#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "tof.h"

struct trace_object *
to_dequeue(struct c_trace_fwd_state *state)
{
	struct trace_object *to, **new_queue;

	to = state->to_queue[0];
	memmove(&state->to_queue[0], &state->to_queue[1], (state->nr_to - 1) * sizeof(struct trace_object *));
	new_queue = reallocarray(state->to_queue, state->nr_to - 1, sizeof(struct trace_object *));
	if (!!new_queue) {
		state->to_queue = new_queue;
		state->nr_to--;
		return to;
	}
	memmove(&state->to_queue[1], &state->to_queue[0], (state->nr_to - 1) * sizeof(struct trace_object *));
	state->to_queue[0] = to;
	return NULL;
}

int
to_dequeue_multi(struct c_trace_fwd_state *state, struct trace_object ***to, int *n)
{
	int nr_to, orig_len;
	struct trace_object **new_q;

	orig_len = *n;
	nr_to = MIN(orig_len, state->nr_to);
	if (!nr_to) {
		free(*to);
		*to = NULL;
		*n = 0;
		return RETVAL_SUCCESS;
	} else if (nr_to < orig_len) {
		struct trace_object **new_to;

		if (!(new_to = reallocarray(*to, nr_to, sizeof(struct trace_object *))))
			return RETVAL_FAILURE;
		*to = new_to;
		*n = nr_to;
	}
	memccpy(*to, state->to_queue, nr_to, sizeof(struct trace_object *));
	memmove(&state->to_queue[0], &state->to_queue[nr_to],
		(state->nr_to - nr_to) * sizeof(struct trace_object *));
	new_q = reallocarray(state->to_queue, state->nr_to - nr_to,
				sizeof(struct trace_object *));
	if (!!new_q) {
		state->to_queue = new_q;
		state->nr_to -= nr_to;
		return RETVAL_SUCCESS;
	}
	memmove(&state->to_queue[nr_to], &state->to_queue[0],
		(state->nr_to - nr_to) * sizeof(struct trace_object *));
	memccpy(state->to_queue, to, nr_to, sizeof(struct trace_object *));
	memset(*to, 0, (*n) * sizeof(struct trace_object *));
	return RETVAL_FAILURE;
}

int
to_enqueue(struct c_trace_fwd_state *state, struct trace_object *to)
{
	struct trace_object **new_queue;

	new_queue = reallocarray(state->to_queue, state->nr_to + 1, sizeof(struct trace_object *));
	if (!new_queue)
		return RETVAL_FAILURE;
	state->to_queue = new_queue;
	state->nr_to++;
	state->to_queue[state->nr_to - 1] = to;
	return RETVAL_SUCCESS;
}

int
to_enqueue_multi(struct c_trace_fwd_state *state, struct trace_object **to, int n)
{
	struct trace_object **new_queue;

	ctf_msg(queue, "entering to_enqueue_multi()\n");
	if (!(new_queue = reallocarray(state->to_queue, state->nr_to + n, sizeof(struct trace_object *)))) {
		ctf_msg(queue, "reallocarray() failed, n = %d, nmemb = %zd, size = %zd\n",
				n, (size_t)(state->nr_to + n), sizeof(struct trace_object *));
		return RETVAL_FAILURE;
	}
	memccpy(&new_queue[state->nr_to], to, n, sizeof(struct trace_object *));
	state->to_queue = new_queue;
	state->nr_to += n;
	ctf_msg(queue, "to_enqueue_multi() succeeded\n");
	return RETVAL_SUCCESS;
}
