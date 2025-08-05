#include <getopt.h>
#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "service.h"

static bool empty_svc_loop(int);

int main(int argc, char *argv[])
{
	int opt, fd;
	gsize path_len;
	char *path = NULL;
	struct sockaddr_un sa;
	int retval = EXIT_FAILURE;

	while ((opt = getopt(argc, argv, "u:")) != -1) {
		switch (opt) {
		case 'u':
			path_len = strlen(optarg) + 1; /* NUL */
			if (path_len > sizeof(sa.sun_path))
				return EXIT_FAILURE;
			memset(&sa, 0, sizeof(sa));
			sa.sun_family = AF_UNIX;
			path = &sa.sun_path[0];
			(void)!strncpy(path, optarg, sizeof(sa.sun_path));
			break;
		default:
			return EXIT_FAILURE;
		}
	}
	if (!path) /* detects whether the -u option got passed */
		return EXIT_FAILURE;
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return EXIT_FAILURE;
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto out_shutdown;
	if (!empty_svc_loop(fd))
		goto out_shutdown;
	retval = EXIT_SUCCESS;
out_shutdown:
	(void)!shutdown(fd, SHUT_RDWR);
	(void)!close(fd);
	return retval;
}

static bool
empty_svc_loop(int fd)
{
	(void)!fd;
	return true;
}
