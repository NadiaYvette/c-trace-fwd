#pragma once

#include <stdarg.h>
#include <unistd.h>

struct ctf_msg_ctx {
	const char *file, *func, *ctx;
	int line;
};

int ctf_msg_core(const struct ctf_msg_ctx *, const char *, ...);

#define ctf_msg(mod, fmt, ...)                                     \
	do {                                                       \
		char __ctx_errstr##__LINE__[]			   \
			= "ctf_msg() failed!\n";		   \
		struct ctf_msg_ctx __ctx_##__LINE__ = {            \
			.func = __func__,                          \
			.file = __FILE__,                          \
			.line = __LINE__,                          \
			.ctx = #mod,                               \
		};                                                 \
		if (ctf_msg_core(&__ctx_##__LINE__,		   \
				 fmt __VA_OPT__ (,) __VA_ARGS__)   \
							< 0) {	   \
			write(STDERR_FILENO,			   \
				__ctx_errstr##__LINE__,		   \
				sizeof(__ctx_errstr##__LINE__));   \
		}						   \
	} while (0)
#define ctf_set_agency(mod, state, new_agency)			   \
	do {							   \
		switch ((state)->agency) {			   \
		case agency_local:				   \
			switch (new_agency) {			   \
			case agency_local:			   \
				ctf_msg(mod, "agency local -> local\n");\
				break;				   \
			case agency_remote:			   \
				ctf_msg(mod, "agency local -> remote\n");\
				break;				   \
			case agency_nobody:			   \
				ctf_msg(mod, "agency local -> nobody\n");\
				break;				   \
			default:				   \
				ctf_msg(mod, "agency local -> <unknown> %d\n", new_agency);\
				break;				   \
			}					   \
			break;					   \
		case agency_remote:				   \
			switch (new_agency) {			   \
			case agency_local:			   \
				ctf_msg(mod, "agency remote -> local\n");\
				break;				   \
			case agency_remote:			   \
				ctf_msg(mod, "agency remote -> remote\n");\
				break;				   \
			case agency_nobody:			   \
				ctf_msg(mod, "agency remote -> nobody\n");\
				break;				   \
			default:				   \
				ctf_msg(mod, "agency remote -> <unknown> %d\n", new_agency);\
				break;				   \
			}					   \
			break;					   \
		case agency_nobody:				   \
			switch (new_agency) {			   \
			case agency_local:			   \
				ctf_msg(mod, "agency nobody -> local\n");\
				break;				   \
			case agency_remote:			   \
				ctf_msg(mod, "agency nobody -> remote\n");\
				break;				   \
			case agency_nobody:			   \
				ctf_msg(mod, "agency nobody -> nobody\n");\
				break;				   \
			default:				   \
				ctf_msg(mod, "agency nobody -> <unknown> %d\n", new_agency);\
				break;				   \
			}					   \
			break;					   \
		default:					   \
			switch (new_agency) {			   \
			case agency_local:			   \
				ctf_msg(mod, "agency <unknown> %d -> local\n", (state)->agency);\
				break;				   \
			case agency_remote:			   \
				ctf_msg(mod, "agency <unknown> %d -> remote\n", (state)->agency);\
				break;				   \
			case agency_nobody:			   \
				ctf_msg(mod, "agency <unknown> %d -> nobody\n", (state)->agency);\
				break;				   \
			default:				   \
				ctf_msg(mod, "agency <unknown> %d -> <unknown> %d\n", (state)->agency, new_agency);\
				break;				   \
			}					   \
		}						   \
		(state)->agency = new_agency;			   \
	} while (0)
