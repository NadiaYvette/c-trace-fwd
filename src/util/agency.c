#include "agency.h"
#include "c_trace_fwd.h"
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
