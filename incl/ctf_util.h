#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <unistd.h>
#include "agency.h"

struct ctf_msg_ctx {
	const char *file, *func, *ctx;
	int line;
};

struct cbor_item_t;

int ctf_msg_core(const struct ctf_msg_ctx *, const char *, ...);
size_t cbor_refcount(const struct cbor_item_t *);

#define ctf_cbor_decref(mod, cbor)				   \
	do {							   \
		size_t __ctx_rc##__LINE__ = cbor_refcount(*(cbor));\
		if ((unsigned long)(cbor) < (1UL << 20))	   \
			ctf_msg(mod, "wild ptr decref %s (%p/<addr not fetched>)\n", #cbor, cbor);\
		else if ((unsigned long)(*(cbor)) < (1UL << 20))   \
			ctf_msg(mod, "wild ptr decref of what %s points to (%p/%p)\n", #cbor, cbor);\
		else if (!__ctx_rc##__LINE__)			   \
			ctf_msg(mod, "refcount zero on %s (%p/%p)\n", #cbor, cbor, *(cbor));\
		else {						   \
			if (__ctx_rc##__LINE__ == 1)		   \
				ctf_msg(mod, "refcount one on %s (%p/%p)\n", #cbor, cbor, *(cbor));\
			cbor_decref(cbor);			   \
		}						   \
	} while (0)

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
		enum agency *__ctx_agency##__LINE__ = &(state)->agency,\
			__ctx_new_agency##__LINE__ = new_agency;   \
		switch (*__ctx_agency##__LINE__) {		   \
		case agency_local:				   \
			switch (__ctx_new_agency##__LINE__) {	   \
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
				ctf_msg(mod, "agency local -> <unknown> %d\n", __ctx_new_agency##__LINE__);\
				break;				   \
			}					   \
			break;					   \
		case agency_remote:				   \
			switch (__ctx_new_agency##__LINE__) {	   \
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
				ctf_msg(mod, "agency remote -> <unknown> %d\n", __ctx_new_agency##__LINE__);\
				break;				   \
			}					   \
			break;					   \
		case agency_nobody:				   \
			switch (__ctx_new_agency##__LINE__) {	   \
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
				ctf_msg(mod, "agency nobody -> <unknown> %d\n", __ctx_new_agency##__LINE__);\
				break;				   \
			}					   \
			break;					   \
		default:					   \
			switch (__ctx_new_agency##__LINE__) {	   \
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
				ctf_msg(mod, "agency <unknown> %d -> <unknown> %d\n", *__ctx_agency##__LINE__, __ctx_new_agency##__LINE__);\
				break;				   \
			}					   \
		}						   \
		*__ctx_agency##__LINE__ = __ctx_new_agency##__LINE__;\
	} while (0)
