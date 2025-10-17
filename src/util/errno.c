#include <errno.h>

#if defined(__linux__)
#include <linux/errno.h>

#if !defined(ERESTART)
#warning "ERESTART not found, using 85"
#define ERESTART     85
#endif /* !defined(ERESTART) */

#if !defined(ERESTARTSYS)
#warning "ERESTARTSYS not found, using 512"
#define ERESTARTSYS 512
#endif /* !defined(ERESTARTSYS) */

#endif /* __linux__ */

bool
errno_is_restart(int errno_value)
{
	return     errno_value == EAGAIN
		|| errno_value == EINTR
#if defined(__linux__)
		|| errno_value == ERESTART
		|| errno_value == ERESTARTSYS
#endif /* __linux__ */
		|| errno_value == EWOULDBLOCK;
}
