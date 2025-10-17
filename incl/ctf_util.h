#pragma once

#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/param.h>
#include "agency.h"
#include "mpn.h"

enum ctf_severity {
	ctf_debug     = 0,
	ctf_info      = 1,
	ctf_notice    = 2,
	ctf_warning   = 3,
	ctf_error     = 4,
	ctf_critical  = 5,
	ctf_alert     = 6,
	ctf_emergency = 7,
};

#define CTF_SEV_MIN_0_to_1 MIN(ctf_debug, ctf_info)
#define CTF_SEV_MIN_2_to_3 MIN(ctf_notice, ctf_warning)
#define CTF_SEV_MIN_0_to_3 MIN(CTF_SEV_MIN_0_to_1, CTF_SEV_MIN_2_to_3)
#define CTF_SEV_MIN_4_to_5 MIN(ctf_error, ctf_critical)
#define CTF_SEV_MIN_6_to_7 MIN(ctf_alert, ctf_emergency)
#define CTF_SEV_MIN_4_to_7 MIN(CTF_SEV_MIN_4_to_5, CTF_SEV_MIN_6_to_7)
#define CTF_SEV_MIN        MIN(CTF_SEV_MIN_0_to_3, CTF_SEV_MIN_4_to_7)

#define CTF_SEV_MAX_0_to_1 MAX(ctf_debug, ctf_info)
#define CTF_SEV_MAX_2_to_3 MAX(ctf_notice, ctf_warning)
#define CTF_SEV_MAX_0_to_3 MAX(CTF_SEV_MAX_0_to_1, CTF_SEV_MAX_2_to_3)
#define CTF_SEV_MAX_4_to_5 MAX(ctf_error, ctf_critical)
#define CTF_SEV_MAX_6_to_7 MAX(ctf_alert, ctf_emergency)
#define CTF_SEV_MAX_4_to_7 MAX(CTF_SEV_MAX_4_to_5, CTF_SEV_MAX_6_to_7)
#define CTF_SEV_MAX        MAX(CTF_SEV_MAX_0_to_3, CTF_SEV_MAX_4_to_7)
#define CTF_SEV_NR	   (CTF_SEV_MAX - CTF_SEV_MIN + 1)

#define CTF_SEV_VALID(ctf_sev)						\
({									\
	enum ctf_severity __ctf_sev_valid_val_##__LINE__ = (ctf_sev);	\
	__ctf_sev_valid_val_##__LINE__ >= CTF_SEV_MIN &&		\
		__ctf_sev_valid_val_##__LINE__ <= CTF_SEV_MAX;		\
})

struct ctf_msg_ctx {
	const char *file, *func, *ctx;
	int line;
};

struct cbor_item_t;

extern enum ctf_severity ctf_sev_lvl;
const char *ctf_severity_string(enum ctf_severity);
int ctf_msg_core(const struct ctf_msg_ctx *, const char *, ...);
size_t cbor_refcount(const struct cbor_item_t *);
bool render_flags_core(const struct ctf_msg_ctx *, int);
void ctf_severity_init(const char *);
bool errno_is_restart(int);

#define CTF_CHK_PTR_LO_ADDR	(((uintptr_t)1) << 20)
#define ctf_check_ptr(mod, ptr)						\
({									\
	void *__ctx_ptr##__LINE__ = (ptr);				\
	bool __ctx_ret##__LINE__					\
		= !!((uintptr_t)__ctx_ptr##__LINE__			\
					< CTF_CHK_PTR_LO_ADDR);		\
	if (__ctx_ret##__LINE__)					\
		ctf_msg(ctf_alert, mod, "wild pointer %s = %p\n",	\
					#ptr,				\
					__ctx_ptr##__LINE__);		\
	__ctx_ret##__LINE__;						\
})

#define ctf_cbor_decref(mod, cbor)					\
do {									\
	size_t __ctx_rc##__LINE__ = cbor_refcount(*(cbor));		\
	if (ctf_check_ptr(mod, cbor))					\
		ctf_msg(ctf_alert, mod, "wild ptr decref %s (%p"	\
				"/<addr not fetched>)\n",		\
				#cbor, cbor);				\
	else if (ctf_check_ptr(mod, *(cbor)))				\
		ctf_msg(ctf_alert, mod, "wild ptr decref of what %s "	\
				"points to (%p/%p)\n", #cbor, cbor);	\
	else if (!__ctx_rc##__LINE__)					\
		ctf_msg(ctf_alert, mod, "refcount zero on "		\
				"%s (%p/%p)\n", #cbor, cbor, *(cbor));	\
	else {								\
		if (__ctx_rc##__LINE__ == 1)				\
			ctf_msg(ctf_debug, mod, "refcount one on "	\
					"%s (%p/%p)\n",			\
					#cbor, cbor, *(cbor));		\
		cbor_decref(cbor);					\
	}								\
} while (0)

#define ctf_msg(sev, mod, fmt, ...)					\
do {									\
	enum ctf_severity __ctf_msg_sev_##__LINE__ = (sev);		\
	char __ctx_errstr##__LINE__[] = "ctf_msg() failed!\n";		\
	struct ctf_msg_ctx __ctx_##__LINE__ = {				\
			.func = __func__,				\
			.file = __FILE__,				\
			.line = __LINE__,				\
			.ctx = #mod,					\
		};							\
	if (CTF_SEV_VALID(__ctf_msg_sev_##__LINE__) &&			\
			__ctf_msg_sev_##__LINE__ >= ctf_sev_lvl) {	\
		if (ctf_msg_core(&__ctx_##__LINE__,			\
				fmt __VA_OPT__ (,) __VA_ARGS__) < 0) {	\
			(void)!write(STDERR_FILENO,			\
					__ctx_errstr##__LINE__,		\
					sizeof(__ctx_errstr##__LINE__));\
		}							\
	}								\
} while (0)

#define ctf_set_agency(mod, ioq, new_agency, mpn)			\
do {									\
	int __ctx_mpn_off##__LINE__;					\
	struct io_queue *__ctx_q##__LINE__ = ioq;			\
	enum mini_protocol_num __ctx_mpn##__LINE__ = mpn;		\
	enum relative_agency *__ctx_agency_ary##__LINE__,		\
		__ctx_old_agency##__LINE__,				\
		__ctx_new_agency##__LINE__ = new_agency;		\
	__ctx_mpn_off##__LINE__ = __ctx_mpn##__LINE__ - MPN_MIN;	\
	__ctx_agency_ary##__LINE__ = (__ctx_q##__LINE__)->agencies;	\
	__ctx_old_agency##__LINE__					\
		= (__ctx_agency_ary##__LINE__)[__ctx_mpn_off##__LINE__];\
	if (RELATIVE_AGENCY_VALID(__ctx_old_agency##__LINE__) &&	\
		RELATIVE_AGENCY_VALID(__ctx_new_agency##__LINE__))	\
		ctf_msg(ctf_debug, mod, "agency [%s] %s -> %s\n",	\
			mini_protocol_string(__ctx_mpn##__LINE__),	\
			relative_agency_string(__ctx_old_agency##__LINE__),\
			relative_agency_string(__ctx_new_agency##__LINE__));\
	else if (RELATIVE_AGENCY_VALID(__ctx_old_agency##__LINE__))	\
		ctf_msg(ctf_error, mod, "agency [%s] %s -> <unknown> %d\n",\
			mini_protocol_string(__ctx_mpn##__LINE__),	\
			relative_agency_string(__ctx_old_agency##__LINE__),\
			__ctx_new_agency##__LINE__);			\
	else if (RELATIVE_AGENCY_VALID(__ctx_new_agency##__LINE__))	\
		ctf_msg(ctf_error, mod, "agency [%s] <unknown> %d -> %s\n",\
			mini_protocol_string(__ctx_mpn##__LINE__),	\
			__ctx_old_agency##__LINE__,			\
			relative_agency_string(__ctx_new_agency##__LINE__));\
	else								\
		ctf_msg(ctf_error, mod, "agency [%s] <unknown> %d "	\
					"-> <unknown> %d\n",		\
			mini_protocol_string(__ctx_mpn##__LINE__),	\
			__ctx_old_agency##__LINE__,			\
			__ctx_new_agency##__LINE__);			\
	io_queue_agency_set(__ctx_q##__LINE__, __ctx_mpn##__LINE__,	\
			__ctx_new_agency##__LINE__);			\
} while (0)

#define render_flags(mod, flags)				    \
	do {                                                        \
		char __ctx_errstr##__LINE__[]			    \
			= "render_flags() failed!\n";		    \
		struct ctf_msg_ctx __ctx_##__LINE__ = {             \
			.func = __func__,                           \
			.file = __FILE__,                           \
			.line = __LINE__,                           \
			.ctx = #mod,                                \
		};                                                  \
		if (!render_flags_core(&__ctx_##__LINE__, flags)) { \
			(void)!write(STDERR_FILENO,		    \
				__ctx_errstr##__LINE__,		    \
				sizeof(__ctx_errstr##__LINE__));    \
		}						    \
	} while (0)

#define render_fd_flags(mod, fd)					\
	do {								\
		char __ctx_render_errstr##__LINE__[]			\
			= "render_flags() failed!\n";			\
		char __ctx_fcntl_errstr##__LINE__[]			\
			= "fcntl() failed!\n";				\
		int __ctx_flags##__LINE__;				\
		struct ctf_msg_ctx __ctx_##__LINE__ = {			\
			.func = __func__,				\
			.file = __FILE__,				\
			.line = __LINE__,				\
			.ctx = #mod,					\
		};							\
		if ((__ctx_flags##__LINE__ = fcntl(fd, F_GETFL)) == -1)	\
			(void)!write(STDERR_FILENO,			\
				__ctx_fcntl_errstr##__LINE__,		\
				sizeof(__ctx_fcntl_errstr##__LINE__));	\
		if (!render_flags_core(&__ctx_##__LINE__,		\
					__ctx_flags##__LINE__)) {	\
			(void)!write(STDERR_FILENO,			\
				__ctx_render_errstr##__LINE__,		\
				sizeof(__ctx_render_errstr##__LINE__));	\
		}							\
	} while (0)
