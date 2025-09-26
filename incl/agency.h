#pragma once
#include <sys/param.h>

/*
 * PeerRole always as client, affecting relative agency
 */
enum peer_role {
	peer_role_client = 0,
	peer_role_server = 1,
};

#define PEER_ROLE_MIN MIN(peer_role_client, peer_role_server)
#define PEER_ROLE_MAX MAX(peer_role_client, peer_role_server)
#define PEER_ROLE_VALID(value)						\
	({								\
		enum peer_role __ctx_role##__LINE__ = (value);		\
		__ctx_role##__LINE__ >= PEER_ROLE_MIN &&		\
			__ctx_role##__LINE__ <= PEER_ROLE_MAX;		\
	})

enum raw_agency {
	raw_agency_client = 0,
	raw_agency_server = 1,
	raw_agency_nobody = 2,
};

#define RAW_AGENCY_MIN \
	MIN(raw_agency_client, MIN(raw_agency_server, raw_agency_nobody))
#define RAW_AGENCY_MAX \
	MAX(raw_agency_client, MAX(raw_agency_server, raw_agency_nobody))
#define RAW_AGENCY_VALID(value)						\
	({								\
		enum raw_agency __ctx_raw_agency##__LINE__ = (value);	\
		__ctx_raw_agency##__LINE__ >= RAW_AGENCY_MIN &&		\
			__ctx_raw_agency##__LINE__ <= RAW_AGENCY_MAX;	\
	})

enum relative_agency {
	relative_agency_we_have    = 0,
	relative_agency_they_have  = 1,
	relative_agency_nobody_has = 2,
};

#define RELATIVE_AGENCY_MIN \
	MIN(relative_agency_we_have, \
		MIN(relative_agency_they_have, relative_agency_nobody_has))
#define RELATIVE_AGENCY_MAX \
	MAX(relative_agency_we_have, \
		MAX(relative_agency_they_have, relative_agency_nobody_has))
#define RELATIVE_AGENCY_VALID(value)					\
({									\
	enum relative_agency __ctx_relative_agency##__LINE__ = (value);	\
	__ctx_relative_agency##__LINE__ >= RELATIVE_AGENCY_MIN &&	\
		__ctx_relative_agency##__LINE__ <= RELATIVE_AGENCY_MAX;	\
})

enum agency {
	agency_local  = 0, /* WeHaveAgency */
	agency_remote = 1, /* TheyHaveAgency */
	agency_nobody = 2, /* NobodyHasAgency */
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
const char *relative_agency_string(enum relative_agency);
