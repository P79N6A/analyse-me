/*
 * @Author: jiamu 
 * @Date: 2018-09-27 13:53:17 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-30 19:40:32
 */


#ifndef _IM_CONFIG_H_
#define _IM_CONFIG_H_


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <ev.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "nids.h"

#include "daq_common.h"

#ifndef UINT8_MAX
#  define UINT8_MAX 0xff
#endif
#ifndef USHRT_MAX
#  define USHRT_MAX  0xffff
#endif
#ifndef UINT16_MAX
#  define UINT16_MAX 0xffff
#endif
#ifndef UINT32_MAX
#  define UINT32_MAX (4294967295U)
#endif

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

#define skip_space(p) ({\
	int _ret = 0;\
	while(*p == ' ' || *p == '\t') {\
		p++;\
		_ret++;\
	}\
	_ret;\
})

#define is_all_digit(d) ({\
	int _ret = 0;\
	char *_s = d;\
	size_t _len = strlen(_s);\
\
	while(isdigit((int)*_s++) && --_len > 0);\
\
	if (_len == 0)\
		_ret = 1;\
	_ret;\
})

#define _is_all_digit(d, s, m) ({\
	int _ret = 0;\
	const char *_s = d;\
	int _len = s, _len1 = 0;\
\
	while(isdigit((int)*_s++) && --_len > 0 && _len1++ < m);\
\
	if (_len == 0)\
		_ret = 1;\
	_ret;\
})


#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define ATTACH_SAVE_PATH            "/etc/traffic-insight/atthchment/"
#define EMAIL_TMP_PATH              "/tmp/email_tmp/"

#define EMAIL_FILE_OVERTIME         (1 * 30 * 24 * 60 * 60)

static inline char *strnstr(const char *haystack, const char *needle,int size)
{
	return strstr(haystack,needle);
}
static inline int setnonblocking(int fd)
{
    int flags;
    if (-1 ==(flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
	}

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
typedef enum
{
    RET_FILEERR = -2,
    RET_FAILED  = -1,
    RET_SUCCESS = 0,
}ENUM_IM_ERRCODE;

typedef struct
{
    ENUM_IM_ERRCODE eErrCode;
    char            strErrDescr[64];
}IM_ERRCODE_DESCR;


typedef struct
{

}VIRTUAL_IM_CONFIG;

const char * im_strerror(int eErrCode);


int write_date(const char *strFileName,void *data,int slLen);
#define         GET_IM_ERR(err)   im_strerror(err)

#endif
