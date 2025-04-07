#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "sdu.h"

int
main(void)
{
	struct sdu sdu;
	union {
		char chars[8];
		uint32_t ints[2];
	} sdu_buf;
	ssize_t ret;
	off_t cur_off, dst_off;
	struct stat stat_buf;
	int retval = EXIT_FAILURE;

	if (sizeof(sdu_buf) != 8)
		ctf_msg(sdu_dissect, "SDU header structure size %z "
				     "unexpected\n", sizeof(sdu_buf));
	if (!!fstat(STDIN_FILENO, &stat_buf))
		ctf_msg(sdu_dissect, "fstat(2) failed, errno = %d\n",
				     errno);
	switch (stat_buf.st_mode & S_IFMT) {
	case S_IFBLK:
		ctf_msg(sdu_dissect, "block device unexpected as "
				     "input file\n");
		break;
	case S_IFCHR:
		ctf_msg(sdu_dissect, "character device unexpected as "
				     "input file\n");
		break;
	case S_IFDIR:
		ctf_msg(sdu_dissect, "directory unexpected as "
				     "input file\n");
		break;
	case S_IFIFO:
		ctf_msg(sdu_dissect, "FIFO unexpected as "
				     "input file\n");
		break;
	case S_IFLNK:
		ctf_msg(sdu_dissect, "symlink unexpected as "
				     "input file\n");
		break;
	case S_IFREG:
		/* This is the expected file type. */
		break;
	case S_IFSOCK:
		ctf_msg(sdu_dissect, "symlink unexpected as "
				     "input file\n");
		break;
	default:
		ctf_msg(sdu_dissect, "undocumented input file type\n");
		break;
	}
restart_loop_from_tell:
	if ((cur_off = lseek(STDIN_FILENO, 0, SEEK_CUR)) < 0) {
		ctf_msg(sdu_dissect, "tell failure, errno = %d\n", errno);
		goto exit_free_buf;
	}
restart_loop:
	if ((ret = read(STDIN_FILENO, sdu_buf.chars, 8)) != 8) {
		if (!ret && !errno)
			/* This is the EOF condition. */
			retval = EXIT_SUCCESS;
		else
			ctf_msg(sdu_dissect, "SDU header read() failure, "
					  "ret = %d, errno = %d\n",
					  ret, errno);
		goto exit_free_buf;
	}
	if (sdu_decode(sdu_buf.ints, &sdu) != RETVAL_SUCCESS) {
		ctf_msg(sdu_dissect, "SDU header sdu_decode() failure\n");
		goto exit_free_buf;
	}
	printf("SDU header at off=%jx\n", (intmax_t)cur_off);
	sdu_print(&sdu);
	if (sdu.sdu_len < sizeof(sdu_buf)) {
		ctf_msg(sdu_dissect, "sdu_len < sizeof(struct sdu), "
				     "trying to keep going anyway\n");
		goto restart_loop_from_tell;
	}
	/* The tell was done before the read. */
	dst_off = cur_off + sdu.sdu_len + sizeof(sdu_buf);
	if (dst_off > stat_buf.st_size) {
		ctf_msg(sdu_dissect, "sdu_len runs past EOF, "
				"dst_off = %jx, "
				"st_size = %jx\n",
				(intmax_t)dst_off,
				(intmax_t)stat_buf.st_size);
		goto exit_free_buf;
	}
	if ((cur_off = lseek(STDIN_FILENO, dst_off, SEEK_SET)) < 0) {
		ctf_msg(sdu_dissect, "tell failure, errno = %d\n", errno);
		goto exit_free_buf;
	} else if (cur_off != dst_off) {
		ctf_msg(sdu_dissect, "lseek to wrong offset, "
				     "dst_off = %jx"
				     "cur_off = %jx",
				     (intmax_t)dst_off, (intmax_t)cur_off);
		goto exit_free_buf;
	}
	goto restart_loop;
	retval = EXIT_SUCCESS;
exit_free_buf:
	return retval;
}
