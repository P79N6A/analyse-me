
/*
 * Copyright (C) snqu network, Inc.
 */

#include "im_config.h"

#define MAXLINE 4*1024
#define DEBUG_LEVEL  LOG_INFO   /* LOG_EMERG, LOG_ALERT, LOG_CRIT,  LOG_ERR,   LOG_WARNING, LOG_NOTICE  , LOG_INFO , LOG_DEBUG */
int syslog_en = 2;
int enablog = 0;

void msgl(const char *const filename, const int line, int level, const char *format, ...)
{
	va_list vlist;

    va_start(vlist, format);

    if (level <= DEBUG_LEVEL) {
        char buf[MAXLINE + 1] = {0};
        time_t ts;
        size_t n = 0;

        time(&ts);
        ctime_r(&ts, buf);
        n = strlen(buf);
        buf[n-1] = ' ';/* skip '\n' */
        snprintf(buf + n, sizeof(buf) - n, "[pid:%u](%s:%d) ", (u_int32_t)getpid(), filename, line);
        n = strlen(buf);
        vsnprintf(buf + n, sizeof(buf) - n, format, vlist);
        strcat(buf, "\n");
        fflush(stdout);     /* in case stdout and stderr are the same */
        fputs(buf, stderr);
        fflush(stderr);

		if (syslog_en) {
	    	//openlog(NULL, LOG_PID, LOG_DAEMON);
		    vsyslog(level, format, vlist);
		   // closelog();
		}
    }

    va_end(vlist);
}

void sys_log(unsigned char level, const char *fmt, ...)
{
	va_list args;

	if (syslog_en)
	{
		va_start(args, fmt);	
		vsyslog(level, fmt, args);
		if (syslog_en > 1)
		{
			vprintf(fmt, args);
			puts("");
		}
		va_end(args);
	}
}
