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
