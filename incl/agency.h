#pragma once
#include <sys/param.h>

enum agency {
	agency_local  = 0,
	agency_remote = 1,
	agency_nobody = 2,
};

#define AGENCY_MIN MIN(agency_local, MIN(agency_nobody, agency_remote))
#define AGENCY_MAX MAX(agency_local, MAX(agency_nobody, agency_remote))
#define AGENCY_VALID(value)						\
	({								\
		enum agency __ctx_agency##__LINE__ = (value);		\
		__ctx_agency##__LINE__ >= AGENCY_MIN &&			\
			__ctx_agency##__LINE__ <= AGENCY_MAX;		\
	})

const char *agency_string(enum agency);
