/*
 * @Author: jiamu 
 * @Date: 2018-11-15 14:56:24 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-15 18:12:01
 */

#if !defined(_INSIGHT_IPC_H)
#define _INSIGHT_IPC_H

#include "im_config.h"

#define DATA_CHECK 0xaabbeecc
#define DEFAULT_INSIGHT_SIZE  4096

typedef enum
{
    _INSIGHT_UNKNOWN = 0,
    _INSIGHT_VIRTUAL,
    _INSIGHT_HTTPLOG,
    _INSIGHT_EMIAL,
    _INSIGHT_HEART,
    _INSIGHT_LOG,
}ENUM_INSIGHT_TYPE;

typedef struct
{
    int slDataType;
    int slDataLen;
    unsigned int  ulDataCheck;
    unsigned char ucData[0];
}IPC_DATA_TYPE;

int change_log_status(int status);
inline void init_heart_beat(void *loop);
inline int init_read_event(void *loop,int fd);
inline int init_write_fd(int fd,void *loop);
inline void * malloc_ipc_data(int type);
inline int notify_insight_data(IPC_DATA_TYPE *pstInsight);
#endif // _INSIGHT_IPC_H

