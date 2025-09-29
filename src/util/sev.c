#include <errno.h>
#include <stdlib.h>
#include "ctf_util.h"

enum ctf_severity ctf_sev_lvl = ctf_notice;

void
ctf_severity_init(const char *str)
{
	long sev_lvl_long;
	enum ctf_severity sev_to_try;

	if (!str) {
		ctf_msg(ctf_alert, sev, "NULL option string\n");
		return;
	}
	sev_lvl_long = strtol(str, NULL, 10);
	if (!!errno) {
		ctf_msg(ctf_alert, sev,
				"invalid verbosity option %s\n", str);
		return;
	}
	sev_to_try = (enum ctf_severity)sev_lvl_long;
	if (!CTF_SEV_VALID(sev_to_try)) {
		ctf_msg(ctf_alert, sev, "invalid verbosity level %ld\n",
				sev_lvl_long);
		return;
	}
	ctf_sev_lvl = sev_to_try;
}
