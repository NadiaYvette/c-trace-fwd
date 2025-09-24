#include "agency.h"
#include "c_trace_fwd.h"
#include "mpn.h"
#include "queue.h"

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

enum agency
io_queue_agency_get(struct io_queue *q, enum mini_protocol_num mpn)
{
	(void)!mpn;
	return q->__agency;
}

void
io_queue_agency_set(struct io_queue *q, enum mini_protocol_num mpn, enum agency agency)
{
	(void)!mpn;
	q->__agency = agency;
}

bool io_queue_agency_any_local(struct io_queue *q)
{
	enum mini_protocol_num mpn;

	for (mpn = MPN_MIN; mpn <= MPN_MAX; ++mpn) {
		if (!MPN_VALID(mpn))
			continue;
		if (q->__agency == agency_local)
			return true;
	}
	return false;
}

bool io_queue_agency_all_nonlocal(struct io_queue *q)
{
	enum mini_protocol_num mpn;

	for (mpn = MPN_MIN; mpn <= MPN_MAX; ++mpn) {
		if (!MPN_VALID(mpn))
			continue;
		if (q->__agency == agency_local)
			return false;
	}
	return true;
}
