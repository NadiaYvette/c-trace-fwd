#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include "agency.h"

struct ctf_msg_ctx {
	const char *file, *func, *ctx;
	int line;
};

struct cbor_item_t;

int ctf_msg_core(const struct ctf_msg_ctx *, const char *, ...);
size_t cbor_refcount(const struct cbor_item_t *);

#define CTF_CHK_PTR_LO_ADDR	(((uintptr_t)1) << 20)
#define ctf_check_ptr(mod, ptr)					   \
	({							   \
		void *__ctx_ptr##__LINE__ = (ptr);		   \
		bool __ctx_ret##__LINE__			   \
		    = !!((uintptr_t)__ctx_ptr##__LINE__		   \
					< CTF_CHK_PTR_LO_ADDR);	   \
		if (__ctx_ret##__LINE__)			   \
			ctf_msg(mod, "wild pointer %s = %p\n",	   \
					#ptr,			   \
					__ctx_ptr##__LINE__);	   \
		__ctx_ret##__LINE__;				   \
	})

#define ctf_cbor_decref(mod, cbor)					\
do {									\
	size_t __ctx_rc##__LINE__ = cbor_refcount(*(cbor));		\
	if (ctf_check_ptr(mod, cbor))					\
		ctf_msg(mod, "wild ptr decref %s (%p"			\
				"/<addr not fetched>)\n",		\
				#cbor, cbor);				\
	else if (ctf_check_ptr(mod, *(cbor)))				\
		ctf_msg(mod, "wild ptr decref of what %s "		\
				"points to (%p/%p)\n", #cbor, cbor);	\
	else if (!__ctx_rc##__LINE__)					\
		ctf_msg(mod, "refcount zero on "			\
				"%s (%p/%p)\n", #cbor, cbor, *(cbor));	\
	else {								\
		if (__ctx_rc##__LINE__ == 1)				\
			ctf_msg(mod, "refcount one on "			\
					"%s (%p/%p)\n",			\
					#cbor, cbor, *(cbor));		\
		cbor_decref(cbor);					\
	}								\
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

#define ctf_set_agency(mod, state, new_agency)				\
do {									\
	enum agency *__ctx_old_agency_ptr##__LINE__			\
			= &(state)->agency,				\
		__ctx_new_agency##__LINE__ = new_agency;		\
	if (AGENCY_VALID(*(__ctx_old_agency_ptr##__LINE__)) &&		\
		AGENCY_VALID(__ctx_new_agency##__LINE__))		\
		ctf_msg(mod, "agency %s -> %s\n",			\
			agency_string(*(__ctx_old_agency_ptr##__LINE__)),\
			agency_string(__ctx_new_agency##__LINE__));	\
	else if (AGENCY_VALID(*(__ctx_old_agency_ptr##__LINE__)))	\
		ctf_msg(mod, "agency %s -> <unknown> %d\n",		\
			agency_string(*(__ctx_old_agency_ptr##__LINE__)),\
			__ctx_new_agency##__LINE__);			\
	else if (AGENCY_VALID(__ctx_new_agency##__LINE__))		\
		ctf_msg(mod, "agency <unknown> %d -> %s\n",		\
			*(__ctx_old_agency_ptr##__LINE__),		\
			agency_string(__ctx_new_agency##__LINE__));	\
	else								\
		ctf_msg(mod, "agency <unknown> %d -> <unknown> %d\n",	\
			*(__ctx_old_agency_ptr##__LINE__),		\
			__ctx_new_agency##__LINE__);			\
	*__ctx_old_agency_ptr##__LINE__					\
		= __ctx_new_agency##__LINE__;				\
} while (0)
