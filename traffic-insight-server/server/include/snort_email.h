/*
 * @Author: jiamu 
 * @Date: 2018-11-07 12:01:46 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-12 20:36:24
 */
#ifndef _SNORT_EMAIL_H_
#define _SNORT_EMAIL_H_

#include "im_config.h"
#include "list.h"
#include "ipc.h"

#define MAX_RECORD_TO 50
#define MAX_HANDLE_ATTCH_NUM 8

typedef enum
{
    _SMTP_UNKNWON = 0,

    _SMTP_HELLO_START,          //C
    _SMTP_HELLO_END,            //S

    _SMTP_AUTH_LOGIN,           //C
    _SMTP_AUTH_NEED_UERNAME,    //S
    _SMTP_AUTH_SEND_UERNAME,    //C
    _SMTP_AUTH_NEED_KEY,        //S
    _SMTP_AUTH_SEND_KEY,        //C
    _SMTP_AUTH_END,             //S

    _SMTP_MAIL_START,
    _SMTP_MAIL_END,

    _SMTP_RCPT_START,              //可能会有多个
    _SMTP_RCPT_END,

    _SMTP_DATA_START,           //C
    _SMTP_DATA_END,             //S

    _SMTP_TRANS_START,          //C
    _SMTP_TRANS_OK,            //S

    _SMTP_TRANS_QUIT,          //C

    _SMTP_REST,
    _SMTP_IGNORE,
}ENUM_SMTP_STATUS;


typedef enum
{
    _POP_UNKNWN = 0,
	_POP_USER,
    _POP_PASS,
    _POP_RETR,
    _POP_QUIT,
}ENUM_POP_STATUS;
 
 
typedef struct
{
    char strContentFile[128];
    char strAttchFile[MAX_HANDLE_ATTCH_NUM * 128];
}EMAIL_EXTRACT_INFO;

typedef struct
{   
    int  slToNum;
    int  dataLen;

    char strSender[32];
    char strKey[128];
    char strTo[MAX_RECORD_TO * 32];;

    EMAIL_EXTRACT_INFO stExtractInfo;
    unsigned char ucSubject[1024];

    char strTmpFile[64];
    unsigned char ucData[0];
}SMTP_PARSE_INFO;

typedef struct
{
    int  dataLen;
    char strUser[32];
    char strKey[128];
    char strRecordTag[8];
    char strId[8] ;
	char strSession[32];
    char strTmpFile[64];
    unsigned char ucData[0];
}IMAP_PARSE_INFO;

typedef enum
{
    _IMAP_UKNNOWN  = 0,
    _IMAP_LOGIN_ = 1,
    _IMAP_FETCH,
}ENUM_IMAP_STATUS;

typedef struct
{
    unsigned int  ulIp;
    unsigned char ucMac[6];
    int  emailType;
    char strUser[32];
    char strKey[128];
    char strTo[MAX_RECORD_TO * 32];
    char strFileName[128];
}EMAIL_INSIGHT_IPC;


typedef enum
{
	_EMAIL_SMTP = 0,
	_EMAIL_IMAP,
	_EMAIL_POP3,
}ENUM_EMAIL_TYPE;

int do_start_smtp(void *pri);
int do_start_imap(void *pri);
int do_start_pop(void *pri);
int do_insight_email(void *data,int slDataLen,int slProtocol,
	void *addr,void *pstEthInfo,int direction,void *pstConn);
int parse_email(char *strFileName,ENUM_EMAIL_TYPE type,void *pstEmail);

#endif
