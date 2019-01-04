/*
 * @Author: jiamu 
 * @Date: 2018-11-15 14:53:41 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-15 17:26:54
 */
#include "im_config.h"
#include "log.h"
#include "ipc.h"
#include "record_data.h"

static int readFd = -1;
static int writeFd = 0;
static ev_io  ipc_watcher;
static ev_io  log_watcher;
static ev_timer tm_watcher;
extern int syslog_en ;

typedef struct
{
    pid_t pid;
    unsigned char data[128];
}HEART_BEAT_INFO;

typedef struct
{
    int enable;
}LOG_STATUS;

static void worker_process_heart(IPC_DATA_TYPE *pstInsight,int len)
{
    if(len < sizeof(HEART_BEAT_INFO))
        return;
    else
    {    
        HEART_BEAT_INFO *pstHeart = pstInsight->ucData;
        pid_t pid = pstHeart->pid;
        printf("Now get subprocess %d heart notify\n",pid);
    }
}
static void ev_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    IPC_DATA_TYPE *pstInsight = calloc(1,sizeof(IPC_DATA_TYPE) + DEFAULT_INSIGHT_SIZE);
    if(pstInsight == NULL)
        return;
    
    int slDataLen = read(readFd,pstInsight,sizeof(IPC_DATA_TYPE) + DEFAULT_INSIGHT_SIZE);
    if(slDataLen < 0 || pstInsight->ulDataCheck != DATA_CHECK)
    {
       goto handle_err;
    }
    
    switch(pstInsight->slDataType)
    {
        case _INSIGHT_VIRTUAL:
            record_virtual_data(pstInsight,slDataLen - sizeof(IPC_DATA_TYPE));
        break;
        case _INSIGHT_HTTPLOG:
            record_http_data(pstInsight,slDataLen - sizeof(IPC_DATA_TYPE));
        break;
        case _INSIGHT_EMIAL:
            record_email_data(pstInsight,slDataLen - sizeof(IPC_DATA_TYPE));
        break;
        case _INSIGHT_HEART:
            worker_process_heart(pstInsight,slDataLen - sizeof(IPC_DATA_TYPE));
        break;
        default:
            WARNING("Get unknwon insight type %d",pstInsight->slDataType);
    }
    
 handle_err:   
    free(pstInsight);
    pstInsight = NULL;
}

inline int init_read_event(void *loop,int fd)
{
    readFd = fd;
    setnonblocking(readFd);

    ev_io_init(&ipc_watcher, ev_read_cb, readFd, EV_READ);
	ev_io_start(loop, &ipc_watcher);

    return RET_SUCCESS;
}
static void heart_beat_notify(struct ev_loop *loop, ev_timer *watcher, int revents)
{
    unsigned char buf[sizeof(HEART_BEAT_INFO) + sizeof(IPC_DATA_TYPE) + 10] = {0};
    IPC_DATA_TYPE *pstInsight = (IPC_DATA_TYPE *)buf;
    pstInsight->slDataType   = _INSIGHT_HEART;
    pstInsight->ulDataCheck  = DATA_CHECK;
    pstInsight->slDataLen    = sizeof(HEART_BEAT_INFO);

    HEART_BEAT_INFO *pstHeart = pstInsight->ucData;
    pstHeart->pid = getpid();

    notify_insight_data(pstInsight);
}
inline void init_heart_beat(void *loop)
{
    ev_timer_init(&tm_watcher, heart_beat_notify, 30, 307);
	ev_timer_start(loop, &tm_watcher);
}

static void ev_subread_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    IPC_DATA_TYPE *pstInsight = calloc(1,sizeof(IPC_DATA_TYPE) + DEFAULT_INSIGHT_SIZE);
    if(pstInsight == NULL)
        return;
    
    int slDataLen = read(writeFd,pstInsight,sizeof(IPC_DATA_TYPE) + DEFAULT_INSIGHT_SIZE);
    if(slDataLen < 0 || pstInsight->ulDataCheck != DATA_CHECK)
    {
       goto handle_err;
    }

    switch(pstInsight->slDataType)
    {
        case _INSIGHT_LOG:
        {
            LOG_STATUS *pstLogInfo = pstInsight->ucData;
            syslog_en = pstLogInfo->enable == true ? 2: 0;
            printf("Get log status %d \n",pstLogInfo->enable);
        }
        break;
        default:
            WARNING("Get unknwon insight type %d",pstInsight->slDataType);
    }

handle_err:   
    free(pstInsight);
    pstInsight = NULL;
}
inline int init_write_fd(int fd,void *loop)
{
    writeFd = fd;
    setnonblocking(writeFd);

    ev_io_init(&log_watcher, ev_subread_cb, writeFd, EV_READ);
	ev_io_start(loop, &log_watcher);
    return RET_SUCCESS;
}

int change_log_status(int status)
{
    unsigned char buf[sizeof(LOG_STATUS) + sizeof(IPC_DATA_TYPE) + 10] = {0};
    IPC_DATA_TYPE *pstInsight = (IPC_DATA_TYPE *)buf;
    pstInsight->slDataType   = _INSIGHT_LOG;
    pstInsight->ulDataCheck  = DATA_CHECK;
    pstInsight->slDataLen    = sizeof(LOG_STATUS);

    LOG_STATUS *pstLogInfo = pstInsight->ucData;
    pstLogInfo->enable = status;

    return (0 < write(readFd,pstInsight,sizeof(IPC_DATA_TYPE) + pstInsight->slDataLen)) ? RET_SUCCESS : RET_FAILED;
}

inline void * malloc_ipc_data(int type)
{
    IPC_DATA_TYPE *pstInsight = calloc(1,sizeof(IPC_DATA_TYPE) + DEFAULT_INSIGHT_SIZE);
    if(pstInsight == NULL)
        return NULL;
    pstInsight->slDataType  = type;
    pstInsight->ulDataCheck = DATA_CHECK;
    return pstInsight;
}

inline int notify_insight_data(IPC_DATA_TYPE *pstInsight)
{
    int len  = sizeof(IPC_DATA_TYPE) + pstInsight->slDataLen;
    return (len == write(writeFd,pstInsight,sizeof(IPC_DATA_TYPE) + pstInsight->slDataLen)) ? RET_SUCCESS : RET_FAILED;
}
