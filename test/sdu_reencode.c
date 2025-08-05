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
	struct sdu new_sdu, old_sdu;
	union sdu_ptr new_sdu_buf = { .sdu8 = (uint8_t *)&new_sdu },
	      old_sdu_buf = { .sdu8 = (uint8_t *)&old_sdu };
	ssize_t ret;
	off_t sdu_payload_off, sdu_read_off, tmp_off;
	struct stat stat_buf;
	int retval = EXIT_FAILURE;
	char *old_buf, *new_buf;

	if (!(new_buf = calloc(64, 1024))) {
		ctf_msg(sdu_reencode, "Buffer allocation failure.\n");
		return EXIT_FAILURE;
	}
	new_sdu_buf.sdu8 = (uint8_t *)new_buf;
	if (!(old_buf = calloc(64, 1024))) {
		ctf_msg(sdu_reencode, "Buffer allocation failure.\n");
		goto free_new_buf;
	}
	old_sdu_buf.sdu8 = (uint8_t *)old_buf;
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
			goto free_old_buf;
		}
		if ((ret = read(STDIN_FILENO, old_buf, 8)) != 8) {
			if (!ret && !errno)
				ctf_msg(sdu_reencode, "EOF? off = %jx\n", (intmax_t)sdu_read_off);
			else
				ctf_msg(sdu_reencode, "SDU header read failure, ret = %zd, errno = %d\n", ret, errno);
			goto free_old_buf;
		}
		old_sdu_buf.sdu8 = (uint8_t *)old_buf;
		sdu_decode(old_sdu_buf, &old_sdu);
		if ((sdu_payload_off = lseek(STDIN_FILENO, 0, SEEK_CUR)) < 0) {
			ctf_msg(sdu_reencode, "tell failure, errno = %d\n", errno);
			goto free_old_buf;
		}
		if ((ret = read(STDIN_FILENO, new_buf, old_sdu.sdu_len)) != old_sdu.sdu_len) {
			if (!ret && !errno)
				ctf_msg(sdu_reencode, "EOF? off = %jx\n", (intmax_t)sdu_payload_off);
			else
				ctf_msg(sdu_reencode, "SDU payload read failure, ret = %zd, errno = %d\n", ret, errno);
			goto free_old_buf;
		}
		new_sdu_buf.sdu8 = (uint8_t *)new_buf;
		sdu_encode(&old_sdu, new_sdu_buf);
		sdu_decode(new_sdu_buf, &new_sdu);
		old_sdu_buf.sdu8 = (uint8_t *)&old_sdu;
		if (memcmp(old_sdu_buf.sdu8, new_sdu_buf.sdu8, 8)) {
			ctf_msg(sdu_reencode, "tell failure, errno = %d\n", errno);
			goto free_old_buf;
		}
		if ((tmp_off = lseek(STDOUT_FILENO, 0, SEEK_CUR)) != sdu_read_off) {
			ctf_msg(sdu_reencode, "bad offset, was %jx supposed to be %jx\n", (intmax_t)tmp_off, (intmax_t)sdu_read_off);
			goto free_old_buf;
		}
		if ((ret = write(STDOUT_FILENO, new_sdu_buf.sdu8, 8)) != 8) {
			ctf_msg(sdu_reencode, "write SDU header failure, ret = %zd, errno = %d\n", ret, errno);
			goto free_old_buf;
		}
		if ((tmp_off = lseek(STDOUT_FILENO, 0, SEEK_CUR)) != sdu_payload_off) {
			ctf_msg(sdu_reencode, "bad offset, was %jx supposed to be %jx\n", (intmax_t)tmp_off, (intmax_t)sdu_payload_off);
			goto free_old_buf;
		}
		if ((ret = write(STDOUT_FILENO, new_buf, new_sdu.sdu_len)) != new_sdu.sdu_len) {
			ctf_msg(sdu_reencode, "write SDU payload failure, ret = %zd, errno = %d\n", ret, errno);
			goto free_old_buf;
		}
	}
	retval = EXIT_SUCCESS;
free_old_buf:
	free(old_buf);
free_new_buf:
	free(new_buf);
	return retval;
}
