#include <cbor.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "tof.h"

static void
print_severity(enum severity_s sev)
{
	switch (sev) {
	case severity_debug:
		printf("\t\tto_severity=debug\n");
		break;
	case severity_info:
		printf("\t\tto_severity=info\n");
		break;
	case severity_notice:
		printf("\t\tto_severity=notice\n");
		break;
	case severity_warning:
		printf("\t\tto_severity=warning\n");
		break;
	case severity_error:
		printf("\t\tto_severity=error\n");
		break;
	case severity_critical:
		printf("\t\tto_severity=critical\n");
		break;
	case severity_alert:
		printf("\t\tto_severity=alert\n");
		break;
	case severity_emergency:
		printf("\t\tto_severity=emergency\n");
		break;
	}
}

static void
print_detail(enum detail_level detail)
{
	switch (detail) {
	case dminimal:
		printf("\t\tto_detail=dminimal\n");
		break;
	case dnormal:
		printf("\t\tto_detail=dnormal\n");
		break;
	case ddetailed:
		printf("\t\tto_detail=ddetailed\n");
		break;
	case dmaximum:
		printf("\t\tto_detail=dmaximum\n");
		break;
	}
}

static void
print_trace_object(struct trace_object *to)
{
	int k;

	printf("\ttrace_object\n");
	printf("\t\tto_human = \"%s\"\n", to->to_human ? to->to_human : "");
	printf("\t\tto_machine = \"%s\"\n", to->to_machine ? to->to_machine : "");
	printf("\t\tto_namespace_nr = %d\n", to->to_namespace_nr);
	for (k = 0; k < to->to_namespace_nr; ++k)
		printf("\t\t\tto_namespace[%d]=\"%s\"\n", k, to->to_namespace[k] ? to->to_namespace[k] : "");
	print_severity(to->to_severity);
	print_detail(to->to_details);
	printf("\t\tto->to_timestamp=%llu\n", (unsigned long long)to->to_timestamp);
	printf("\t\tto_hostname = \"%s\"\n", to->to_hostname ? to->to_hostname : "");
	printf("\t\tto_thread_id = \"%s\"\n", to->to_thread_id ? to->to_thread_id : "");
}

int
main(void)
{
	cbor_item_t *item;
	struct cbor_load_result cbor_load_result;
	struct trace_object *to;
	unsigned char *buf;
	ssize_t ret;
	int retval = EXIT_FAILURE;

	if (!(buf = calloc(1024, 1024)))
		return EXIT_FAILURE;
	if ((ret = read(STDIN_FILENO, buf, 1024 * 1024)) < 0)
		goto exit_free_buf;;
	if (!(item = cbor_load(buf, ret, &cbor_load_result)))
		goto exit_free_buf;;
	if (!(to = trace_object_decode(item)))
		goto exit_cbor_decref;
	print_trace_object(to);
	retval = EXIT_SUCCESS;
	trace_object_free(to);
exit_cbor_decref:
	cbor_decref(&item);
exit_free_buf:
	free(buf);
	return retval;
}
