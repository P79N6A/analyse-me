/*
 * @Author: jiamu 
 * @Date: 2018-10-17 20:03:40 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-15 17:53:18
 */
#ifndef _RECORD_DATA_H_
#define _RECORD_DATA_H_
#include "im_config.h"
#include "snort_file.h"

typedef struct data_record
{
    //struct list_head    list;
    struct data_record *nextaccout; /*for multi accout,such as threre are some qqnums in one phone*/
    time_t              stTimeStamp; /*最后一次更新时间,取决是否删除这个数据*/
    char strTypeName[16];
    int    isRecordToDb;
    int    eRecordType;
    int    slRecordLen;
    unsigned char ucData[0];
}DATA_RECORD_INFO;

typedef struct
{
    /*base id*/
    unsigned char    ucMacAddr[6];
    unsigned short   usDataCount;          /*总共记录了多少条数据*/
    unsigned int     ulIPAddr;
    time_t           stTimeStamp;          /*最后一次更新时间，取决是否删除这个终端*/
    struct list_head listTerm;             /*next terminal*/
    /*record data*/
    //struct list_head listData[_TARGET_MAX]; 
    DATA_RECORD_INFO *pstDataRecord[_TARGET_MAX];
}TERM_RECORD_INFO;

/**
 * @brief 
 *  value可能是由多个账号用+隔绝
 */
typedef struct
{
    int num;
    char strType[16];
    char value[256];
}ACCOUNT_TYPE_INFO;

/*用于ipc通信*/
typedef struct
{
    unsigned int  ulIp;
    unsigned char ucMac[6];
    ACCOUNT_TYPE_INFO stAccountInfo;
}VIRTUAL_IPC_DATA;

/**
 * @brief 
 * 客户端请求数据
 */
typedef struct
{
    int  log;
    int  slIndex;
    char strMac[32];
	char strIp[32] ; 	
	char strType[32]; 
    char strVal[256]; 
	char strStartOnlineDate[32];
	char strStartOnlineTime[32] ;
	char strEndOnlineDate[32] ;
	char strEndOnlineTime[32] ;

	char strStartActiveDate[32] ;
	char strStartActiveTime[32] ;
	char strEndActiveDate[32];
	char strEndActiveTime[32];
}CLIENT_REQ_INFO;

int record_init(struct ev_loop *loop);
int virtual_ubus_init(struct ev_loop *loop);
int do_record_data(void *data,int len,void *pri);

void record_virtual_data(void *data,int slDataLen);
void record_http_data(void *data,int slDataLen);
void record_email_data(void *data,int slDataLen);
#endif
