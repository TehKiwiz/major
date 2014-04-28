
#ifndef ERROR_H
#define ERROR_H

#include <errno.h>


#define GOTERR		-1
#define ERRNODATA	-2

void set_error(char *file, int line, int errnum, char *fmt, ...);
void print_error();
void _err_msg(char *file, int line, int errnum, char *fmt, ...);


#define return_error(fmt, ...)						\
do {									\
	set_error(__FILE__, __LINE__, errno, fmt, ##__VA_ARGS__);	\
	return GOTERR;							\
} while(0)

#define err_msg(fmt, ...) \
	_err_msg(__FILE__, __LINE__, errno, fmt, ##__VA_ARGS__)


#endif
