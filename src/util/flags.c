#include <fcntl.h>
#include <string.h>
#include "ctf_util.h"

#define BIT(k) (((uint64_t)1) << (k))
#define ISSET(mask, k) (!!((mask) & BIT(k)))
#define LG0(N)  ((N) >= (1 <<  0) ?  0 : (-1))
#define LG1(N)  ((N) >= (1 <<  1) ?  1 : LG0(N))
#define LG2(N)  ((N) >= (1 <<  2) ?  2 : LG1(N))
#define LG3(N)  ((N) >= (1 <<  3) ?  3 : LG2(N))
#define LG4(N)  ((N) >= (1 <<  4) ?  4 : LG3(N))
#define LG5(N)  ((N) >= (1 <<  5) ?  5 : LG4(N))
#define LG6(N)  ((N) >= (1 <<  6) ?  6 : LG5(N))
#define LG7(N)  ((N) >= (1 <<  7) ?  7 : LG6(N))
#define LG8(N)  ((N) >= (1 <<  8) ?  8 : LG7(N))
#define LG9(N)  ((N) >= (1 <<  9) ?  9 : LG8(N))
#define LG10(N) ((N) >= (1 << 10) ? 10 : LG9(N))
#define LG11(N) ((N) >= (1 << 11) ? 11 : LG10(N))
#define LG12(N) ((N) >= (1 << 12) ? 12 : LG11(N))
#define LG13(N) ((N) >= (1 << 13) ? 13 : LG12(N))
#define LG14(N) ((N) >= (1 << 14) ? 14 : LG13(N))
#define LG15(N) ((N) >= (1 << 15) ? 15 : LG14(N))
#define LG16(N) ((N) >= (1 << 16) ? 16 : LG15(N))
#define LG17(N) ((N) >= (1 << 17) ? 17 : LG16(N))
#define LG18(N) ((N) >= (1 << 18) ? 18 : LG17(N))
#define LG19(N) ((N) >= (1 << 19) ? 19 : LG18(N))
#define LG20(N) ((N) >= (1 << 20) ? 20 : LG19(N))
#define LG21(N) ((N) >= (1 << 21) ? 21 : LG20(N))
#define LG22(N) ((N) >= (1 << 22) ? 22 : LG21(N))
#define LG23(N) ((N) >= (1 << 23) ? 23 : LG22(N))
#define LG24(N) ((N) >= (1 << 24) ? 24 : LG23(N))
#define LG25(N) ((N) >= (1 << 25) ? 25 : LG24(N))
#define LG26(N) ((N) >= (1 << 26) ? 26 : LG25(N))
#define LG27(N) ((N) >= (1 << 27) ? 27 : LG26(N))
#define LG28(N) ((N) >= (1 << 28) ? 28 : LG27(N))
#define LG29(N) ((N) >= (1 << 29) ? 29 : LG28(N))
#define LG(N)   ((N) >= (1 << 30) ? 30 : LG29(N))

#define INITFLG(FLG) [LG(FLG)] = { .mask = FLG, .name = #FLG }
#define FLAG_TBL_MAX (sizeof(flag_tbl)/sizeof(flag_tbl[0]))

struct {
	unsigned mask;
	const char *name;
} flag_tbl[] = {
	// [LG(O_WRONLY)] = { .mask = O_WRONLY, .name = "O_WRONLY", },
	// [LG(O_RDWR)] = { .mask = O_RDWR, .name = "O_RDWR", },
	INITFLG(O_WRONLY),
	INITFLG(O_RDWR),
	INITFLG(O_EXCL),
	INITFLG(O_NOCTTY),
	INITFLG(O_TRUNC),
	INITFLG(O_APPEND),
	INITFLG(O_NONBLOCK),
	INITFLG(O_SYNC),
	INITFLG(O_ASYNC),
#ifdef O_LARGEFILE
	INITFLG(O_LARGEFILE),
#endif
	INITFLG(O_DIRECTORY),
	INITFLG(O_NOFOLLOW),
	INITFLG(O_CLOEXEC),
#ifdef O_NOATIME
	INITFLG(O_NOATIME),
#endif
#ifdef O_PATH
	INITFLG(O_PATH),
#endif
	INITFLG(O_DSYNC),
};

bool
render_flags_core(const struct ctf_msg_ctx *ctx, int flags)
{
	unsigned k;
	char *cur_buf, buf[4096] = { [0 ... 4095] = '\0' };

	for (cur_buf = buf, k = 0; k < MIN(UINT32_WIDTH, FLAG_TBL_MAX); ++k) {
		if (!ISSET(flags, k))
			continue;
		if (!flag_tbl[k].name)
			continue;
		if (cur_buf != buf)
			cur_buf = stpcpy(cur_buf, " | ");
		if (ISSET(flags, k) && k < FLAG_TBL_MAX && !!flag_tbl[k].name)
			cur_buf = stpcpy(cur_buf, flag_tbl[k].name);
	}
	ctf_msg_core(ctx, "0x%x = %s\n", flags, buf);
	return true;
}
