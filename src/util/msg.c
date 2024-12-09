#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ctf_util.h"

static int
vsnprintf_alloc(char **ret, const char *fmt, ...)
{
	ssize_t to_print, buf_len = 1024;
	va_list args;

retry_alloc:
	*ret = calloc((size_t)buf_len, sizeof(char));
	if (!*ret)
		return -1;
	va_start(args, fmt);
	to_print = vsnprintf(*ret, buf_len, fmt, args);
	va_end(args);
	if (0 < to_print && to_print < buf_len)
		return 0;
	free(*ret);
	*ret = NULL;
	if (to_print < 0)
		return -1;
	buf_len *= 2;
	goto retry_alloc;
}

int
ctf_msg_core(const struct ctf_msg_ctx *ctx, const char *fmt, ...)
{
	char *tmp_fmt, *pfx = NULL;
	size_t len;
	va_list args;
	int retval = -1;

	if (vsnprintf_alloc(&pfx, "[%s] %s (%s:%d) ", ctx->ctx,
				ctx->func, ctx->file, ctx->line))
		return retval;

	len = strlen(fmt) + strlen(pfx) + 1;
	tmp_fmt = calloc(len, sizeof(char));
	if (!tmp_fmt)
		goto exit_free_pfx;
	strcpy(tmp_fmt, pfx);
	strcat(tmp_fmt, fmt);
	va_start(args, fmt);
	retval = vfprintf(stderr, tmp_fmt, args);
	va_end(args);
	retval = retval > 0 ? 0 : -1;
	free(tmp_fmt);
exit_free_pfx:
	free(pfx);
	return retval;
}
