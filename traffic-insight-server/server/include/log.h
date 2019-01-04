
/*
 * Copyright (C) snqu network, Inc.
 */

#ifndef __LOG_H__
#define __LOG_H__

extern int enablog;

#define STD_BUF 1024
void sys_log(unsigned char level, const char *fmt, ...);
void msgl(const char * const filename, int line, int level, const char *format, ...);
#ifdef DBUG
#define print(fmt...) msgl(__FILE__,__LINE__,LOG_ERR,fmt)
#define print_dbg(fmt...)
#define print_rule(fmt...)
#define printpkt(fmt...) msgl(__FILE__,__LINE__,LOG_ERR,fmt)
//#define print_rule(fmt...) msgl(__FILE__,__LINE__,LOG_ERR,fmt)
#else
#define print(fmt...)
#define print_dbg(fmt...)
#define print_rule(fmt...)
#define printpkt(fmt...)
#endif

#define INFO(fmt, args...) 	  sys_log(LOG_INFO, "[%s|%d] "fmt"\n", __func__, __LINE__, ##args)
#define WARNING(fmt, args...) sys_log(LOG_WARNING, "[%s|%d] "fmt"\n", __func__, __LINE__, ##args)
#define ERROR(fmt, args...)   sys_log(LOG_ERR, "[%s|%d] "fmt"\n", __func__, __LINE__, ##args)


#define fatal(fmt...) ({\
    msgl(__FILE__,__LINE__,LOG_ERR,fmt);\
    abort();\
})



#define FatalError(fmt...)  print_dbg(fmt)
#define LogMessage(fmt...)  print_dbg(fmt)

#define dmark if (enablog) print("in %s.", __FUNCTION__)
#endif
