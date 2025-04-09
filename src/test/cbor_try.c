#include <cbor.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "ctf_util.h"

int main(int argc, char *argv[])
{
	int fd;
	unsigned char *map;
	struct stat stat_buf;
	size_t page_size, page_mask, file_len, len, off;
	struct cbor_load_result result;
	cbor_item_t *item;

	if (argc != 2)
		return EXIT_FAILURE;
	if ((fd = open(argv[1], O_RDONLY)) < 0)
		return EXIT_FAILURE;
	if (fstat(fd, &stat_buf) < 0)
		return EXIT_FAILURE;
	page_size = sysconf(_SC_PAGE_SIZE);
	if (__builtin_popcount(page_size) != 1)
		return EXIT_FAILURE;
	page_mask = page_size - 1;
	len = stat_buf.st_size;
	file_len = (len + page_mask) & ~page_mask;
	if (!(map = mmap(NULL, file_len, PROT_READ, MAP_SHARED, fd, 0)))
		return EXIT_FAILURE;
	for (off = 0; off < stat_buf.st_size; ++off, --len) {
		if (!(item = cbor_load(&map[off], len, &result)))
			continue;
		printf("success at off 0x%jx, len 0x%zx\n", off, len);
		cbor_describe(item, stdout);
		cbor_decref(&item);
	}
	return EXIT_SUCCESS;
}

#if 0
int
main(int argc, char *argv[])
{
	int fd;
	off_t off;
	size_t len, min_len, max_len;
	ssize_t ret;
	unsigned char *buf;

	if (argc - 1 != 4) {
		ctf_msg(cbor_try, "argc = %d wrong\n", argc);
		return EXIT_FAILURE;
	}
	if (!(buf = calloc(1024, 1024)))
		return EXIT_FAILURE;
	if ((fd = open(argv[1], O_RDONLY)) < 0)
		return EXIT_FAILURE;
	if (sscanf(argv[2], "0x%jx", &off) < 0)
		return EXIT_FAILURE;
	if (sscanf(argv[3], "0x%zx", &min_len) < 0)
		return EXIT_FAILURE;
	if (sscanf(argv[4], "0x%zx", &max_len) < 0)
		return EXIT_FAILURE;
	if ((ret = pread(fd, buf, max_len, off)) < 0)
		return EXIT_FAILURE;
	printf("0x%zx read\n", ret);
	for (len = min_len; len <= max_len; ++len) {
		struct cbor_load_result result;
		cbor_item_t *item;

		if (!(item = cbor_load(buf, len, &result)))
			continue;
		printf("decode at offset 0x%jx len %zx succeeds, "
				"size %zx\n", off, len, result.read);
		cbor_describe(item, stdout);
		cbor_decref(&item);
	}
	return EXIT_SUCCESS;
}
#endif
