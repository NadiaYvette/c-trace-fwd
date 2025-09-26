#include "agency.h"
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "mpn.h"
#include "queue.h"

const char *
agency_string(enum agency agency)
{
	static const char default_string[] = "invalid agency";
	static const char *agency_table[] = {
		[agency_local]  = "agency_local",
		[agency_nobody] = "agency_nobody",
		[agency_remote] = "agency_remote",
	};

	if (AGENCY_VALID(agency))
		return agency_table[agency];
	return default_string;
}

const char *
raw_agency_string(enum raw_agency agency)
{
	static const char default_string[] = "invalid raw agency";
	static const char *string_table[] = {
		[raw_agency_client] = "raw_agency_client",
		[raw_agency_server] = "raw_agency_server",
		[raw_agency_nobody] = "raw_agency_nobody",
	};

	if (RAW_AGENCY_VALID(agency))
		return string_table[agency];
	return default_string;
}

const char *
relative_agency_string(enum relative_agency agency)
{
	static const char default_string[] = "invalid relative agency";
	static const char *string_table[] = {
		[relative_agency_we_have] = "relative_agency_we_have",
		[relative_agency_they_have] = "relative_agency_they_have",
		[relative_agency_nobody_has] = "relative_agency_nobody_has",
	};

	if (RELATIVE_AGENCY_VALID(agency))
		return string_table[agency];
	return default_string;
}

enum relative_agency
io_queue_agency_get(struct io_queue *q, enum mini_protocol_num mpn)
{
	enum relative_agency agency;

	if (!MPN_VALID(mpn)) {
		ctf_msg(agency, "invalid mpn %d\n", (int)mpn);
		return (enum relative_agency)(-1);
	}
	agency = q->agencies[mpn - MPN_MIN];
	if (!RELATIVE_AGENCY_VALID(agency)) {
		ctf_msg(agency, "invalid agency %d\n", (int)agency);
		return (enum relative_agency)(-1);
	}
	return q->agencies[mpn - MPN_MIN];
}

void
io_queue_agency_set(struct io_queue *q, enum mini_protocol_num mpn, enum relative_agency agency)
{
	if (!RELATIVE_AGENCY_VALID(agency)) {
		ctf_msg(agency, "invalid agency %d\n", (int)agency);
		return;
	}
	if (!MPN_VALID(mpn)) {
		ctf_msg(agency, "invalid mpn %d\n", (int)mpn);
		return;
	}
	q->agencies[mpn - MPN_MIN] = agency;
}

bool io_queue_agency_any_local(struct io_queue *q)
{
	enum mini_protocol_num mpn;

	for (mpn = MPN_MIN; mpn <= MPN_MAX; ++mpn) {
		if (!MPN_VALID(mpn))
			continue;
		if (q->agencies[mpn - MPN_MIN] == relative_agency_we_have)
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
		if (q->agencies[mpn - MPN_MIN] == relative_agency_we_have)
			return false;
	}
	return true;
}
