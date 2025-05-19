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
	} __attribute__((packed)) __attribute((__aligned__(8))) new_sdu_buf, old_sdu_buf;
	ssize_t ret;
	off_t sdu_payload_off, sdu_read_off, tmp_off;
	struct stat stat_buf;
	int retval = EXIT_FAILURE;
	char *buf;

	if (!(buf = calloc(1024, 1024)))
		ctf_msg(sdu_reencode, "Buffer allocation failure.\n");
	if (sizeof(old_sdu_buf) != 8)
		ctf_msg(sdu_reencode, "SDU header structure size %z "
				      "unexpected\n", sizeof(old_sdu_buf));
	if (!!fstat(STDIN_FILENO, &stat_buf))
		ctf_msg(sdu_reencode, "fstat(2) failed, errno = %d\n",
				      errno);
	switch (stat_buf.st_mode & S_IFMT) {
	case S_IFBLK:
		ctf_msg(sdu_reencode, "block device unexpected as "
				      "input file\n");
		break;
	case S_IFCHR:
		ctf_msg(sdu_reencode, "character device unexpected as "
				      "input file\n");
		break;
	case S_IFDIR:
		ctf_msg(sdu_reencode, "directory unexpected as "
				      "input file\n");
		break;
	case S_IFIFO:
		ctf_msg(sdu_reencode, "FIFO unexpected as "
				      "input file\n");
		break;
	case S_IFLNK:
		ctf_msg(sdu_reencode, "symlink unexpected as "
				      "input file\n");
		break;
	case S_IFREG:
		/* This is the expected file type. */
		break;
	case S_IFSOCK:
		ctf_msg(sdu_reencode, "symlink unexpected as "
				      "input file\n");
		break;
	default:
		ctf_msg(sdu_reencode, "undocumented input file type\n");
		break;
	}
	for (;;) {
		if ((sdu_read_off = lseek(STDIN_FILENO, 0, SEEK_CUR)) < 0) {
			ctf_msg(sdu_reencode, "tell failure, errno = %d\n", errno);
			goto exit_free_buf;
		}
		if ((ret = read(STDIN_FILENO, old_sdu_buf.chars, sizeof(old_sdu_buf))) != sizeof(old_sdu_buf)) {
			if (!ret && !errno)
				ctf_msg(sdu_reencode, "EOF? off = %jx\n", (intmax_t)sdu_read_off);
			else
				ctf_msg(sdu_reencode, "SDU header read failure, ret = %zd, errno = %d\n", ret, errno);
			goto exit_free_buf;
		}
		sdu_decode(old_sdu_buf.ints, &sdu);
		if ((sdu_payload_off = lseek(STDIN_FILENO, 0, SEEK_CUR)) < 0) {
			ctf_msg(sdu_reencode, "tell failure, errno = %d\n", errno);
			goto exit_free_buf;
		}
		if ((ret = read(STDIN_FILENO, buf, sdu.sdu_len)) != sdu.sdu_len) {
			if (!ret && !errno)
				ctf_msg(sdu_reencode, "EOF? off = %jx\n", (intmax_t)sdu_payload_off);
			else
				ctf_msg(sdu_reencode, "SDU payload read failure, ret = %zd, errno = %d\n", ret, errno);
			goto exit_free_buf;
		}
		sdu_encode(&sdu, new_sdu_buf.ints);
		if (memcmp(&old_sdu_buf, &new_sdu_buf, sizeof(old_sdu_buf))) {
			ctf_msg(sdu_reencode, "tell failure, errno = %d\n", errno);
			goto exit_free_buf;
		}
		if ((tmp_off = lseek(STDOUT_FILENO, 0, SEEK_CUR)) != sdu_read_off) {
			ctf_msg(sdu_reencode, "bad offset, was %jx supposed to be %jx\n", (intmax_t)tmp_off, (intmax_t)sdu_read_off);
			goto exit_free_buf;
		}
		if ((ret = write(STDOUT_FILENO, new_sdu_buf.chars, sizeof(new_sdu_buf))) != sizeof(new_sdu_buf)) {
			ctf_msg(sdu_reencode, "write SDU header failure, ret = %zd, errno = %d\n", ret, errno);
			goto exit_free_buf;
		}
		if ((tmp_off = lseek(STDOUT_FILENO, 0, SEEK_CUR)) != sdu_payload_off) {
			ctf_msg(sdu_reencode, "bad offset, was %jx supposed to be %jx\n", (intmax_t)tmp_off, (intmax_t)sdu_payload_off);
			goto exit_free_buf;
		}
		if ((ret = write(STDOUT_FILENO, buf, sdu.sdu_len)) != sdu.sdu_len) {
			ctf_msg(sdu_reencode, "write SDU payload failure, ret = %zd, errno = %d\n", ret, errno);
			goto exit_free_buf;
		}
	}
	retval = EXIT_SUCCESS;
exit_free_buf:
	return retval;
}
