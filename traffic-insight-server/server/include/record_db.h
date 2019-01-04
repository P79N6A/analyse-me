/*
 * @Author: jiamu 
 * @Date: 2018-10-19 16:08:20 
 * @Last Modified by:   jiamu 
 * @Last Modified time: 2018-10-19 16:08:20 
 */


#ifndef _RECORD_DB_H_
#define _RECORD_DB_H_

typedef struct
{
    int slId;
    int  slAcountNum;
    char strMac[32];
    char strIp[32];
    char strAccountType[16];
    char strAccountVal[256];
    char strOnlineTime[32];
    char strActiveTime[32];
}DATABASE_RECORD_ENTRY;

typedef struct
{
    int slId;
    char strMac[32];
    char strIp[32];
    char strUrl[1024];
    char strOnlineTime[32];
}HTTP_DB_ENTRY;

typedef struct
{
    int slId;
    char strMac[32];
    char strIp[32];
    char strUser[32];
    char strKey[128];
    char strDir[8];
     char strOnlineTime[32];
    #define MAX_RECORD_TO 50
    #define MAX_HANDLE_ATTCH_NUM 8
    char strFrom[32];
    char strTo[MAX_RECORD_TO * 32];
    char ucSubject[1024];
    char strContent[128];
    char strAttach[MAX_HANDLE_ATTCH_NUM * 128];
}EMAIL_DB_ENTRY;

int do_find_terminal(char *strCmd,int *pslEntryNum,DATABASE_RECORD_ENTRY **ppentry);
int do_find_url(char *strCmd,int *pslEntryNum,HTTP_DB_ENTRY **ppentry);
int do_find_email(char *strCmd,int *pslEntryNum,EMAIL_DB_ENTRY **ppentry);
int do_update_terminal(const void *term,void *account,void *entryInfo);
int do_update_email(void *pstemailInfo,void * ipc);
int do_delete_overtime_term(void);
int do_update_url(void *pstUrlInfo);
int virtual_db_init(void);
#endif

