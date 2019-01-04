/*
 * @Author: jiamu 
 * @Date: 2018-11-07 12:00:53 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-14 17:05:02
 */
#include "snort_file.h"
#include "list.h"
#include "record_data.h"
#include "protocol.h"
#include "cJSON.h"
#include "log.h"
#include "snort_email.h"
#include <cencode.h>
#include <cdecode.h>
#include <iconv.h>


#define SMTP_PORT 25
#define IAMP_PORT 143
#define POP_PORT  110

typedef struct
{
	char strCmdBuf[64];
	int  eCmdStatus;
}CMD_STATUS;

typedef enum
{
	SMTP_READY = 220,
	SMTP_BYE = 221,
	SMTP_AUTHOK = 235,
	SMTP_MAILOK = 250,
	SMTP_INPUT = 334,
	SMTP_STARTMAIL = 354,
	SMTP_ENOTAVAIL = 421,
	SMTP_ELOCAL = 451,
	SMTP_ESTORAGE = 452,
	SMTP_ESYNTAX = 500,
	SMTP_EARGSYNTAX = 501,
	SMTP_ECMDNIMPL = 502,
	SMTP_EBADSEQ = 503,
	SMTP_EARGNIMPL = 504
}ENUM_SMTP_RESCODE;


#define CMD_MATCHES(str, cmd, str_len) (strncasecmp (str, cmd, str_len) == 0)

#define debug_email(str,len,line)
#define DEFAILT_CACHE_BUF_SIZE (16 * 1024)

const static char delim = ' ';
const static char *gstrSubject 		= "\r\nSubject: ";
const static char *gstrContentType 	= "Content-Type:";
const static char *gstrTypeMixed    = "multipart/mixed";
//const static char *gstrTypeRelated  = "multipart/related";
const static char *gstrTypeAlter    = "multipart/alternative";
const static char *gstBoundary      = "boundary=";
const static char *gstTranEncode    = "Content-Transfer-Encoding";

const static CMD_STATUS stCmdStatus[] = 
{
	{"HELO",_SMTP_HELLO_START},
	{"EHLO",_SMTP_HELLO_START},
	{"AUTH",_SMTP_AUTH_LOGIN},
	{"MAIL",_SMTP_MAIL_START},
	{"RCPT",_SMTP_RCPT_START},
	{"DATA",_SMTP_DATA_START},
	{"QUIT",_SMTP_TRANS_QUIT},
	{"REST",_SMTP_REST},

	{"VRFY",_SMTP_IGNORE},
	{"EXPN",_SMTP_IGNORE},
	{"HELP",_SMTP_IGNORE},
	{"NOOP",_SMTP_IGNORE},

};

const static CMD_STATUS stResStatus[] = 
{
	{"Service ready"				,SMTP_READY},
	{"Bye"							,SMTP_BYE},
	{"Auth successful"				,SMTP_AUTHOK},
	{"OK"							,SMTP_MAILOK},
	{"INPUT"						,SMTP_INPUT},
	{"End data with ."				,SMTP_STARTMAIL},
	{"Local error"					,SMTP_ELOCAL},
	{"Not enough storage available",SMTP_ESTORAGE},
	{"Syntax error"					,SMTP_ESYNTAX},
	{"Syntax error in parameter"	,SMTP_EARGSYNTAX},
	{"Syntax error"					,SMTP_ESYNTAX},
	{"Command not implemented"		,SMTP_ECMDNIMPL},
	{"Syntax error"					,SMTP_ESYNTAX},
	{"Bad command sequence"			,SMTP_EBADSEQ},
	{"Command parameter not implemented",SMTP_EARGNIMPL},
};
const static CMD_STATUS stPOPCmdStatus[] = 
{
	{"USER",_POP_USER},
	{"PASS",_POP_PASS},
	{"RETR",_POP_RETR},
	{"QUIT",_POP_QUIT},
};

//int parse_email(char *strFileName,ENUM_EMAIL_TYPE type);
int handle_imap4_protocol(void *data,int slDataLen,int slProtocol,
	struct tuple4 *addr,struct ethhdr *pstEthInfo,int direction,NIDS_CONNTRACK_RECORD *pstConn);
int handle_pop_protocol(void *data,int slDataLen,int slProtocol,
	struct tuple4 *addr,struct ethhdr *pstEthInfo,int direction,NIDS_CONNTRACK_RECORD *pstConn);

static inline int notify_email_insight(void *data,int type,unsigned char *ucMac,unsigned int ip)
{
	unsigned char ucBufData[sizeof(IPC_DATA_TYPE) + sizeof(EMAIL_INSIGHT_IPC) + 10] = {0};
	IPC_DATA_TYPE *pstIpcData = (IPC_DATA_TYPE *)ucBufData;
	EMAIL_INSIGHT_IPC *pstEmailInfo = (EMAIL_INSIGHT_IPC *)pstIpcData->ucData;

	pstIpcData->ulDataCheck = DATA_CHECK;
	pstIpcData->slDataType  = _INSIGHT_EMIAL;
	pstIpcData->slDataLen   = sizeof(EMAIL_INSIGHT_IPC);
	pstEmailInfo->emailType = type;

	pstEmailInfo->ulIp   = ip;
	memcpy(pstEmailInfo->ucMac,ucMac,6);

	if(type == _EMAIL_SMTP)
	{
		SMTP_PARSE_INFO *pstParse = (SMTP_PARSE_INFO *)data;
		strncpy(pstEmailInfo->strUser,pstParse->strSender,ARRAY_SIZE(pstEmailInfo->strUser));
		strncpy(pstEmailInfo->strKey,pstParse->strKey,ARRAY_SIZE(pstEmailInfo->strKey));
		memcpy(pstEmailInfo->strTo,pstParse->strTo,sizeof(pstParse->strTo));
		strncpy(pstEmailInfo->strFileName,pstParse->strTmpFile,ARRAY_SIZE(pstEmailInfo->strFileName));
	}
	else
	{
		IMAP_PARSE_INFO *pstParse = (IMAP_PARSE_INFO *)data;
		strncpy(pstEmailInfo->strUser,pstParse->strUser,ARRAY_SIZE(pstEmailInfo->strUser));
		strncpy(pstEmailInfo->strKey,pstParse->strKey,ARRAY_SIZE(pstEmailInfo->strKey));
		strncpy(pstEmailInfo->strFileName,pstParse->strTmpFile,ARRAY_SIZE(pstEmailInfo->strFileName));
	}
	
	return notify_insight_data(pstIpcData);
}

static int imap_callback_hook(void *stream)
{
	struct tcp_stream *pstTcp = stream;

	NIDS_CONNTRACK_RECORD *pstConn = &pstTcp->stConnInfo;
	char *strFileName = NULL;
	if(pstConn->ucData == NULL)
	{
		return RET_SUCCESS;
	}
	int type = _EMAIL_SMTP;
	if(pstConn->eMainType == _TARGET_SMTP)
	{
		SMTP_PARSE_INFO *pstEmailParse   = pstConn->ucData;
		strFileName    					 = pstEmailParse->strTmpFile;
	}
	else
	{ 
		type = _EMAIL_IMAP;
		IMAP_PARSE_INFO *pstEmailParse   = pstConn->ucData;
		strFileName   					 = pstEmailParse->strTmpFile;
	}
	
	if(strlen(strFileName) == 0)
	{
		return RET_FAILED;
	}

	INFO("Now need parse email info %s by close function",strFileName);
	notify_email_insight(pstConn->ucData,type,pstTcp->stEthInfo.h_source,pstTcp->addr.saddr);

	//unlink(strFileName);

	return RET_FAILED;
}


int write_date(const char *strFileName,void *data,int slLen)
{
	int ret = RET_FAILED;
	int fd  = 0;
	if(access(strFileName,R_OK) == 0)
    {
		fd = open(strFileName,O_WRONLY|O_APPEND);
    }
	else
	{
		fd = open(strFileName,O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG|S_IRWXO);
	}
	
	if(fd < 0)
	{
		return ret;
	}
	ret = write(fd,data,slLen) == slLen ? RET_SUCCESS : RET_FAILED;
	close(fd);
	return ret;
}

static inline int base64_decode(void* input,int len,void* output)
{
	char* c = output;
	int  cnt = 0;
	base64_decodestate s;
	base64_init_decodestate(&s);
	cnt = base64_decode_block(input, len, c, &s);
	c += cnt;
	*c = 0;
	return cnt;
}
static inline int charsettoutf8(void* input,int slInputLen,void* output,int slOutLen ,char *charset)
{
	const char *strUseChar = (strcasecmp(charset,"GB2312") == 0  || strcasecmp(charset,"gb18030") == 0)? "GBK" : charset;
	size_t slRowLen = slInputLen;
	size_t slTransCode = slOutLen;
	iconv_t cd = iconv_open("UTF-8",strUseChar);
	if (cd == (iconv_t)-1)
	{
		INFO("iconv_open from %s to utf8 \n",strUseChar);
		return RET_FAILED;
	}
	const char *strInput = input;
	char *strOut   = output;
	
	size_t ret = iconv(cd, &strInput, &slRowLen,&strOut, &slTransCode);
	if (ret == -1)
	{
		perror ("iconv");
	}
	iconv_close(cd);
	size_t useLen = (size_t)(slOutLen) - slTransCode;
	return (int)useLen;
}


static inline int parse_smtp_request (unsigned int *reqCmd, const char *buff, size_t len)
{
	if ( len == 0 )
		return RET_FAILED;
	int i = 0;
	for(i = 0;i < sizeof(stCmdStatus) / sizeof(stCmdStatus[0]);i++)
	{
		if(CMD_MATCHES(buff,stCmdStatus[i].strCmdBuf,strlen(stCmdStatus[i].strCmdBuf)))
		{
			*reqCmd = stCmdStatus[i].eCmdStatus;
			INFO("Get client cmd %s ",stCmdStatus[i].strCmdBuf);
			return RET_SUCCESS;
		}
	}

	return RET_FAILED;
}

static inline int parse_smtp_response_code(int *code,const char *buff, size_t len)
{
	char strResCode[4] = {0};
	memcpy(strResCode,buff,3);
	printf("smtp Get rescode %s \n",strResCode);

	if(_is_all_digit(buff, 3, 3)) 
	{
		*code = atoi(strResCode);
		return RET_SUCCESS;
	}
	return RET_FAILED;
	
	// if ( len == 0 )
	// 	return RET_FAILED;
	// int i = 0;
	// for(i = 0;i < sizeof(stResStatus) / sizeof(stResStatus[0]);i++)
	// {
	// 	char strBuf[32] = {0};
	// 	snprintf(strBuf,32,"%d",stResStatus->eCmdStatus);
	// 	if(CMD_MATCHES(buff,strBuf,strlen(strBuf)))
	// 	{
	// 		*code = stResStatus->eCmdStatus;
	// 		return RET_SUCCESS;
	// 	}
	// }
}
static inline int dispatch_crlf_data(void *data,int len)
{
	unsigned char *strTmp = NULL;

	if((strTmp = (unsigned char *)strstr((char*)data,"\r\n")) != NULL)
	{
		return (strTmp - (unsigned char *)data);
	}
	return RET_FAILED;
} 

int do_start_smtp(void *pri)
{
	m_priv_t *pstPri = (m_priv_t *)pri;
	NIDS_CONNTRACK_RECORD *pstConn = (NIDS_CONNTRACK_RECORD *)pstPri->pstconn;

	return parse_smtp_request(&pstConn->slUsrType,pstPri->data,pstPri->dlen);
}


int parse_smtp_text(const void * const data,int slDataLen,SMTP_PARSE_INFO *pstParseInfo)
{
	int i = 0,j = 0,k = 0;
	char *strData 	=  (char *)data;
	char *strSubject = NULL;
	char *strMainContentType = NULL;
	int slTmpLen = slDataLen;
	int fd = 0;
	char strTmp[512] 			= {0};
	char strChartSet[32] 		= {0};
	char strEncode[16]    		= {0};
	char strTransferEncode[32] 	= {0};
	char strAttchName[512]      = {0};
	char strAttchNameTmp[512]   = {0};
	size_t slFileSize = 0;
	size_t slFileBound = 0;

	int fileIndex = 0;
	unsigned char *ucDataRow   = NULL;
	unsigned char *ucDataTrans = NULL;

	debug_email(strAttchNameTmp,12,__LINE__);

	if((strSubject = strstr(strData,gstrSubject)) != NULL)
	{
		strSubject = strSubject + strlen(gstrSubject);  //空格
		slTmpLen   = slDataLen - (strSubject - strData);
		int slSubjectLen = dispatch_crlf_data(strSubject,slTmpLen);
		/**
		 * @brief 
		 * 主题可能存在编码的问题
		 */
		
		//if(strncmp(strSubject,"=?",2) == 0) /*有编码*/
		if(sscanf(strSubject,"%*[^?]?%16[^?]?%8[^?]?%1024[^?]",strChartSet,strEncode,strAttchName) == 3)
		{
			//sscanf(strSubject,"%*[^?]?%16[^?]?%8[^?]?%1024[^?]",strChartSet,strEncode,strAttchName);
			j = base64_decode(strAttchName,strlen(strAttchName),strAttchNameTmp);
			bzero(pstParseInfo->ucSubject,ARRAY_SIZE(pstParseInfo->ucSubject));
			k = charsettoutf8(strAttchNameTmp,j,pstParseInfo->ucSubject,ARRAY_SIZE(pstParseInfo->ucSubject),strChartSet);
		}
		else
		{
			memcpy(pstParseInfo->ucSubject,strSubject,slSubjectLen < ARRAY_SIZE(pstParseInfo->ucSubject) ? slSubjectLen : ARRAY_SIZE(pstParseInfo->ucSubject));
		}
		printf("Get subject:%s\ncharset:%s\nencode:%s\n",pstParseInfo->ucSubject,strChartSet,strEncode);
	}
	debug_email(strAttchNameTmp,12,__LINE__);
	if((strMainContentType = strstr(strData,gstrTypeMixed)) != NULL)/*表示有附件*/
	{
		bzero(strTmp,ARRAY_SIZE(strTmp));
		INFO("Now get Email MIME type with attachment \n");
		if((strSubject = strstr(strMainContentType,gstBoundary)) == NULL)
		{
			WARNING("Get %s %s failed %s ",gstrTypeMixed,gstBoundary,strMainContentType);
			return RET_FAILED;
		}
		sscanf(strSubject,"%*[^\"]\"%256[^\"]",strTmp);
		strSubject += (strlen(strTmp) + strlen(gstBoundary));
		char *strFindAttach = NULL;
		printf("Get mixed %s --> %s \n",gstBoundary,strTmp);
		/*跳过非附件部分*/
		if((strFindAttach = strstr(strSubject,strTmp)) == NULL)
		{
			WARNING("Get %s %s failed ",gstrTypeMixed,gstBoundary);
			return RET_FAILED;
		}
		/*开始处理附件部分*/
		
		debug_email(strFindAttach,128,__LINE__);

		strSubject = strFindAttach + (strlen(strTmp) + strlen(gstBoundary));

		for(i = 0;i < MAX_HANDLE_ATTCH_NUM && ((strFindAttach = strstr(strSubject,strTmp)) != NULL);i++)
		//if((strFindAttach = strstr(strSubject,strTmp)))
		{
			fd = 0;
			strFindAttach += strlen(strTmp);
			strSubject = strFindAttach;
			debug_email(strFindAttach,128,__LINE__);
			strMainContentType = strstr(strSubject,gstrContentType);

			if(NULL == strMainContentType ||
			(strMainContentType - strSubject) > 5) /*在边界的下一行紧接着就应该是内容*/
			{
				break;
				//return -1;
			}
			
			strFindAttach = strstr(strMainContentType,"name");
			if(NULL == strFindAttach)
				break;
				//return -1;
			bzero(strAttchName,ARRAY_SIZE(strAttchName));
			bzero(strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp));
			
			if(sscanf(strFindAttach,"%*[^\"]\"%256[^\"]",strAttchName) != 1) /*文件名可能没有以引号包裹*/
			{
				sscanf(strFindAttach,"%*[^=]=%256[^\r]",strAttchName); /*name=xxxx\r\n*/
			}

			if(strlen(strAttchName) == 0)
			{
				snprintf(strAttchName,30,"%s",strFindAttach);
				WARNING("Not get attchname,format may be incompatible --> segment is %s ",strAttchName);
				break;
			}
			strFindAttach += strlen(strAttchName);

			debug_email(strAttchName,128,__LINE__);
			/*判断名字是否是编码的*/
			#if 0
			/*由于文件系统不支持中文名显示,会导致文件名出错,这里对附件名不转换*/
			if(strncmp(strAttchName,"=?",2) == 0) /*有编码*/
			{
				printf("Line = %d \n",__LINE__);
				sscanf(strAttchName,"%*[^?]?%16[^?]?%8[^?]?%256[^?]",strChartSet,strEncode,strAttchNameTmp);
				bzero(strAttchName,ARRAY_SIZE(strAttchName));
				/*解码*/
				printf("Get name:size %d %s\n",strlen(strAttchNameTmp),strAttchNameTmp);
				j = base64_decode(strAttchNameTmp,strlen(strAttchNameTmp),strAttchName);
		
				bzero(strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp));
				charsettoutf8(strAttchName,j,strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp),strChartSet);
				bzero(strAttchName,ARRAY_SIZE(strAttchName));
				memcpy(strAttchName,strAttchNameTmp,ARRAY_SIZE(strAttchName));
			}
			#endif
			printf("Now get attachment name %s \n",strAttchName);
			/*attachmen size is unkown*/
			strMainContentType = strstr(strFindAttach,gstTranEncode);
			// if(NULL == strMainContentType ||
			// 	(strMainContentType - strFindAttach) > 20)/*下一行紧接着就应该是传输格式*/
			if(NULL == strMainContentType)
			{
				WARNING("Get attchment %s transferencode failed",strAttchName);
				break;
			}
			
			bzero(strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp));
			sscanf(strMainContentType,"%*[^ ] %64[^\n]",strAttchNameTmp);
			if(strncasecmp(strAttchNameTmp,"base64",strlen("base64")) != 0)
			{
				WARNING("Get attchment %s transferencode isnot base64",strAttchName);
				break;
			}
			// strFindAttach = strstr(strMainContentType,"filename");
			// if(NULL == strFindAttach)
			// {
			// 	WARNING("Get attchment %s filename segment failed",strAttchName);
			// 	break;
			// }
			// j = 0;
			// if((j = dispatch_crlf_data(strFindAttach,0)) < 0)
			// {
			// 	WARNING("Get attchment  data failed due to  not find start crlf");
			// 	break;
			// }
			// strFindAttach = strFindAttach + j + 4;  /*这里是起始位置*/

			if((strFindAttach = strstr(strMainContentType,"\r\n\r\n")) == NULL)
			{
				WARNING("Get attchment  data failed due to  not find start crlf");
				break;
			}
			strFindAttach = strFindAttach + 4;  /*这里是起始位置*/

			snprintf(strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp),"%s%s",ATTACH_SAVE_PATH,strAttchName);
		
			if((strlen(pstParseInfo->stExtractInfo.strAttchFile) + strlen(strAttchNameTmp) +2) < ARRAY_SIZE(pstParseInfo->stExtractInfo.strAttchFile))
			{
				strcat(pstParseInfo->stExtractInfo.strAttchFile,strAttchNameTmp);
				strcat(pstParseInfo->stExtractInfo.strAttchFile,";");
			}
				
			/*find maincontent type*/
			strMainContentType = strstr(strFindAttach,strTmp);
			if(strMainContentType == NULL)
			{
				WARNING("Get attchment %s data failed end boudoury",strAttchName);
				snprintf(strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp),"touch %s",strAttchName); /*解析失败也做一个记录*/
				system(strAttchNameTmp);
				break;
			}
			strMainContentType = strMainContentType - 4;  /*这里应该是邮件中附件的结束点*/
			slFileBound = strMainContentType - strFindAttach;
			fd = open(strAttchNameTmp,O_CREAT|O_TRUNC|O_WRONLY,S_IRWXU|S_IRWXG|S_IRWXO);
			if(fd < 0)
			{
				WARNING("open attchment %s file %s failed",strAttchName,strAttchNameTmp);
				break;
			}
			ucDataRow = calloc(1,16*1024);
			if(NULL == ucDataRow)
			{
				WARNING("NOT GET MEM");
				break;
			}
			ucDataTrans = calloc(1,16*1024);
			if(NULL == ucDataTrans)
			{
				free(ucDataRow);
				WARNING("NOT GET MEM");
				break;
			}
			fileIndex  = 0;
			slFileSize = 0;
			/*邮件中的格式是分行的，每行数据以\r\n结尾*/
			while(slFileSize < slFileBound && strFindAttach < strMainContentType)
			{
				k = j = 0;
				#if 0
				bzero(strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp));
				if((j = dispatch_crlf_data(strFindAttach,0)) < 0)
				{
					WARNING("Get attchment %s data failed due to  not find end crlf",strAttchName);
					break;
				}
				/*解base64*/
				k = base64_decode(strFindAttach,j,strAttchNameTmp);
				if(write(fd,strAttchNameTmp,k) != k)
				{
					WARNING("write attachment failded");
					break;
				}
				slFileSize += j;
				strFindAttach = strFindAttach + j + 2;

				INFO("Get attachment %s,row size is %u \n",strAttchName,j);
				#else

				if((j = dispatch_crlf_data(strFindAttach,0)) < 0)
				{
					WARNING("Get attchment %s data failed due to  not find end crlf",strAttchName);
					break;
				}
				memcpy(ucDataRow + fileIndex,strFindAttach,j);

				fileIndex  += j;
				slFileSize += j;
				strFindAttach = strFindAttach + j + 2;
				if(fileIndex > (12 * 1024))
				{
					k = base64_decode(ucDataRow,fileIndex,ucDataTrans);
					if(write(fd,ucDataTrans,k) != k)
					{
						WARNING("write attachment failded");
						break;
					}
					fileIndex = 0;
					memset(ucDataRow,0,16 * 1024);
					memset(ucDataTrans,0,16 * 1024);
				}
				#endif

			}
			if(fileIndex != 0)
			{
				k = base64_decode(ucDataRow,fileIndex,ucDataTrans);
				if(write(fd,ucDataTrans,k) != k)
				{
					free(ucDataRow);
					free(ucDataTrans);
					close(fd);
					WARNING("write attachment failded");
					break;
				}
			}
			free(ucDataRow);
			free(ucDataTrans);
			close(fd);
		}
	}
	printf("Now start get text \n");
	/*不关心内嵌资源，直接提取正文,正文不直接存储在数据库，仍然存储文件，将文件名存储在数据库中*/
	if((strMainContentType = strstr(strData,gstrTypeAlter)) != NULL)/*正文部分*/
	{
		bzero(strTmp,ARRAY_SIZE(strTmp));
		INFO("Now get Email text part");
		if((strSubject = strstr(strMainContentType,gstBoundary)) == NULL)
		{
			WARNING("Get %s %s failed ",gstrTypeAlter,gstBoundary);
			return RET_FAILED;
		}
		sscanf(strSubject,"%*[^\"]\"%256[^\"]",strTmp);
		strSubject += (strlen(strTmp) + strlen(gstBoundary));
		char *strFindText = NULL;
		printf("Get alternative %s --> %s ",gstBoundary,strTmp);
		/*第一个位置就是要处理的正文，后面如果还有，则是html部分*/
		if((strFindText = strstr(strSubject,strTmp)) == NULL)
		{
			WARNING("Get %s %s failed ",gstrTypeAlter,gstBoundary);
			return RET_FAILED;
		}
		bzero(strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp));
		bzero(strChartSet,ARRAY_SIZE(strChartSet));
		strFindText = strFindText + strlen(strTmp) + 2;/*现在是content-type*/
		//sscanf(strFindText,"%*[^ ] %64[^;]%*[^\"]\"%32[^\"]",strAttchNameTmp,strChartSet); /*获取content-type 和charset*/
		sscanf(strFindText,"%*[^ ] %64[^;]%*[^=]=%32[^\r]",strAttchNameTmp,strChartSet); /*获取content-type 和charset*/
		if(strChartSet[0] == '"')
		{
			bzero(strAttchName,ARRAY_SIZE(strAttchName));
			sscanf(&strChartSet[1],"%32[^\"]",strAttchName);
			bzero(strChartSet,ARRAY_SIZE(strChartSet));
			strcpy(strChartSet,strAttchName);
		}
		strMainContentType = strstr(strFindText,gstTranEncode);  /*传输格式*/
		strFindText = strFindText + strlen(gstrContentType) + strlen(strAttchNameTmp) + strlen(strChartSet);
		// if(NULL == strMainContentType ||
		// 		(strMainContentType - strFindText) > 20)
		if(NULL == strMainContentType)
		{
			WARNING("Get text part transferencode failed");
			return RET_FAILED;
		}
		INFO("Get text content-type-->%s<-- charset-->%s<--",strAttchNameTmp,strChartSet);
		bzero(strTransferEncode,ARRAY_SIZE(strTransferEncode));
		sscanf(strMainContentType,"%*[^ ] %64[^\r]",strTransferEncode);
		if(strncasecmp(strTransferEncode,"base64",strlen("base64")) != 0)
		{
			WARNING("Get content transer encode isnot base64");
		}
		strFindText = strstr(strMainContentType,"\r\n\r\n");
		if(strFindText == NULL)
		{
			WARNING("Get text part failed due to not find data start");
			return RET_FAILED;
		}
		strFindText += 4;
		// strMainContentType = strstr(strFindText,strTmp);
		// if(strMainContentType == NULL)
		// {
		// 	WARNING("Get tesxt part data failed end boudoury");
		// 	return RET_FAILED;
		// }
		// strMainContentType = strMainContentType - 4;  /*这里应该是邮件中正文的结束点*/
		strMainContentType = strstr(strFindText,"\r\n\r\n");
		if(strMainContentType == NULL)
		{
			WARNING("Get tesxt part data failed end boudoury");
			return RET_FAILED;
		}
		slFileBound = strMainContentType - strFindText;
		
		bzero(strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp));
		bzero(strAttchName,ARRAY_SIZE(strAttchName));
        time_t nowTime = time(NULL);
        strftime(strAttchNameTmp,128,"%Y-%m-%d--%H-%M-%S",localtime(&nowTime));
		snprintf(strAttchName,ARRAY_SIZE(strAttchName),"%semail_%s.content",ATTACH_SAVE_PATH,strAttchNameTmp);
		strncpy(pstParseInfo->stExtractInfo.strContentFile,strAttchName,ARRAY_SIZE(pstParseInfo->stExtractInfo.strContentFile));

		fd = open(strAttchName,O_CREAT|O_TRUNC|O_WRONLY,S_IRWXU|S_IRWXG|S_IRWXO);
		if(fd < 0)
		{
			WARNING("open email text file %s failed",strAttchName);
			return RET_FAILED;
		}
		
		ucDataRow = calloc(1,16*1024);
		if(NULL == ucDataRow)
		{
			WARNING("NOT GET MEM");
			return RET_FAILED;
		}
		ucDataTrans = calloc(1,16*1024);
		if(NULL == ucDataTrans)
		{
			free(ucDataRow);
			WARNING("NOT GET MEM");
			return RET_FAILED;
		}
		fileIndex  = 0;
		slFileSize = 0;
		/*邮件中的格式是分行的，每行数据以\r\n结尾*/
		while(slFileSize < slFileBound && strFindText < strMainContentType)
		{
			k = j = 0;
			#if 0
			bzero(strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp));
			bzero(strAttchName,ARRAY_SIZE(strAttchName));
			if((j = dispatch_crlf_data(strFindText,0)) < 0)
			{
				WARNING("Get attchment %s data failed due to  not find end crlf",strAttchName);
				break;
			}
			/*解base64*/
			k = base64_decode(strFindText,j,strAttchName);
			/*这里需要转码*/
			charsettoutf8(strAttchName,k,strAttchNameTmp,ARRAY_SIZE(strAttchNameTmp),strChartSet);

			if(write(fd,strAttchNameTmp,strlen(strAttchNameTmp)) != strlen(strAttchNameTmp))
			{
				WARNING("write email text failded");
				break;
			}
			slFileSize += j;
			strFindText = strFindText + j + 2;
			#else
			if((j = dispatch_crlf_data(strFindText,0)) < 0)
			{
				WARNING("Get attchment %s data failed due to  not find end crlf",strAttchName);
				break;
			}
			memcpy(ucDataRow + fileIndex,strFindText,j);

			fileIndex  += j;
			slFileSize += j;
			strFindText = strFindText + j + 2;
			if(fileIndex > (12 * 1024))
			{
				k = base64_decode(ucDataRow,fileIndex,ucDataTrans);
				memset(ucDataRow,0,16 * 1024);
				j = charsettoutf8(ucDataTrans,k,ucDataRow,16 * 1024,strChartSet);

				if(write(fd,ucDataRow,j) != j)
				{
					WARNING("write attachment failded");
					break;
				}
				fileIndex = 0;
				memset(ucDataRow,0,16 * 1024);
				memset(ucDataTrans,0,16 * 1024);
			}
			#endif
			
		}
		if(fileIndex != 0)
		{
			k = base64_decode(ucDataRow,fileIndex,ucDataTrans);
			memset(ucDataRow,0,16 * 1024);
			j = charsettoutf8(ucDataTrans,k,ucDataRow,16 * 1024,strChartSet);

			if(write(fd,ucDataRow,j) != j)
			{
				free(ucDataRow);
				free(ucDataTrans);
				close(fd);
				WARNING("write attachment failded");
				return RET_FAILED;
			}
		}
		free(ucDataTrans);
		free(ucDataRow);
		close(fd);

	}
	return RET_SUCCESS;
}

int handle_smtp_protocol(void *data,int slDataLen,int slProtocol,
	struct tuple4 *addr,struct ethhdr *pstEthInfo,int direction,NIDS_CONNTRACK_RECORD *pstConn)
{
	int ret = RET_SUCCESS;
	unsigned char *dataTmp = data;
	int slLastStatus = pstConn->slUsrType;
	int slNewStatus  = _SMTP_IGNORE;
	int slValidLen = -1;
	unsigned char ucStream[128] = {0};
	unsigned char ucDecodeInfo[256] = {0};
	SMTP_PARSE_INFO *pstParseInfo = pstConn->ucData;
	
	if(direction == IP_CT_DIR_ORIGINAL)
	{
		if(parse_smtp_request((unsigned int *)&slNewStatus,data,slDataLen) < 0)
		{
			/*某些命令暂时不识别*/
			if(slLastStatus == _SMTP_AUTH_NEED_UERNAME)
			{
				//解析用户名
				slValidLen = dispatch_crlf_data(data,slDataLen);
				if(slValidLen < 0)
				{
					ret = RET_FAILED;
					goto err;
				}
				memcpy(ucStream,data,slValidLen < ARRAY_SIZE(ucStream) ? slValidLen : ARRAY_SIZE(ucStream));
				base64_decode(ucStream,slValidLen,ucDecodeInfo);
				strncpy(pstParseInfo->strSender,(char *)ucDecodeInfo,ARRAY_SIZE(pstParseInfo->strSender));

				printf("Now get mail sender to %s \n",(char *)ucDecodeInfo);
				slNewStatus = _SMTP_AUTH_SEND_UERNAME;
			}
			else if(slLastStatus == _SMTP_AUTH_NEED_KEY)
			{
				//解析密码
				slValidLen = dispatch_crlf_data(data,slDataLen);
				if(slValidLen < 0)
				{
					ret = RET_FAILED;
					goto err;
				}
				memcpy(ucStream,data,slValidLen < ARRAY_SIZE(ucStream) ? slValidLen : ARRAY_SIZE(ucStream));
				base64_decode(ucStream,slValidLen,ucDecodeInfo);
				strncpy(pstParseInfo->strKey,(char *)ucDecodeInfo,ARRAY_SIZE(pstParseInfo->strKey));

				printf("Now get mail sender key to %s \n",(char *)ucDecodeInfo);
				slNewStatus = _SMTP_AUTH_SEND_KEY;
			}
			else if(slLastStatus == _SMTP_DATA_END)
			{
				#if 0 
				pstConn->ucData = realloc(pstConn->ucData,sizeof(SMTP_PARSE_INFO) + pstParseInfo->dataLen + slDataLen);
				if(NULL == pstConn->ucData)
				{
					ret = RET_FAILED;
					goto err;
				}
				pstParseInfo = pstConn->ucData;
				memset((unsigned char *)pstParseInfo + sizeof(SMTP_PARSE_INFO) + pstParseInfo->dataLen,0,slDataLen);
				memcpy((unsigned char *)pstParseInfo + sizeof(SMTP_PARSE_INFO) + pstParseInfo->dataLen,data,slDataLen);
				pstParseInfo->dataLen += slDataLen;
				#else
				if((pstParseInfo->dataLen + slDataLen) < DEFAILT_CACHE_BUF_SIZE)
				{
					memcpy(pstParseInfo->ucData + pstParseInfo->dataLen,data,slDataLen);
					pstParseInfo->dataLen += slDataLen;
				}
				else
				{
					int fd = 0;
					/*需要写文件*/
					if(strlen(pstParseInfo->strTmpFile) != 0)
					{
						fd = open(pstParseInfo->strTmpFile,O_WRONLY|O_APPEND);
						if(fd < 0)
						{
							WARNING("Open file failed %s",pstParseInfo->strTmpFile);
							//goto handle_err;
						}
					}
					else
					{	time_t nowTime = time(NULL);
						char strTimeStamp[128] = {0};
						strftime(strTimeStamp,128,"%H-%M-%S",localtime(&nowTime));

						snprintf(pstParseInfo->strTmpFile,ARRAY_SIZE(pstParseInfo->strTmpFile),"%semail_%02x%02x%02x%02x%02x%02x_%s",
						EMAIL_TMP_PATH,
						pstEthInfo->h_dest[0],pstEthInfo->h_dest[1],pstEthInfo->h_dest[2],pstEthInfo->h_dest[3],pstEthInfo->h_dest[4],pstEthInfo->h_dest[5],
						strTimeStamp);

						fd = open(pstParseInfo->strTmpFile,O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG|S_IRWXO);
						if(fd < 0)
						{
							WARNING("Open file failed %s",pstParseInfo->strTmpFile);
							//goto handle_err;
						}
						//pstConn->callClose = imap_callback_hook;
					}
					if(fd > 0)
					{
						if(write(fd,pstParseInfo->ucData,pstParseInfo->dataLen) != pstParseInfo->dataLen)
						{
							WARNING("write %d date to %s failed ",pstParseInfo->dataLen,pstParseInfo->strTmpFile);
						}
						if(write(fd,data,slDataLen) != slDataLen)
						{
							WARNING("write %d date to %s failed ",slDataLen,pstParseInfo->strTmpFile);
						}
						close(fd);

						pstParseInfo->dataLen = 0;
						memset(pstParseInfo->ucData,0,DEFAILT_CACHE_BUF_SIZE);
					}	
				}
				#endif
				slNewStatus = _SMTP_DATA_END;
			}
		}

		if(slNewStatus == _SMTP_RCPT_START)
		{
			//解析接受者
			slValidLen = dispatch_crlf_data(data,slDataLen);
			if(slValidLen < 0)
			{
				ret = RET_FAILED;
				goto err;
			}
			memcpy(ucStream,data,slValidLen < ARRAY_SIZE(ucStream) ? slValidLen : ARRAY_SIZE(ucStream));
			// char *strStart = strchr(ucStream,'<');
			// char *strEnd   = strchr(ucStream,'>');
			// int nameLen    = 0;
			// if(!strStart || !strEnd)
			// {
			// 	ret = RET_FAILED;
			// 	goto err;
			// }
			// strStart += 1;
			sscanf((char *)ucStream,"%*[^<]<%64[^>]",(char *)ucDecodeInfo);
			int nameLen = strlen((char *)ucDecodeInfo);
			//base64_decode(ucStream,ucDecodeInfo);
			if(pstParseInfo->slToNum < MAX_RECORD_TO)
			{
				strcat(pstParseInfo->strTo,ucDecodeInfo);
				strcat(pstParseInfo->strTo,";");
				pstParseInfo->slToNum++;
			}
			printf("!!!!!Now get mail to %s \n",(char *)ucStream);
		}
	}
	else
	{
		int resCode = 0;
		parse_smtp_response_code(&resCode,data,slDataLen);

		switch(slLastStatus)
		{
			case _SMTP_HELLO_START:
			{
				if(resCode != SMTP_MAILOK)
				{
					ret = RET_FAILED;
					break;
				}

				ret = RET_SUCCESS;
				slNewStatus = _SMTP_HELLO_END;
				SMTP_PARSE_INFO *pstParseInfoTmp = calloc(1,sizeof(SMTP_PARSE_INFO) + DEFAILT_CACHE_BUF_SIZE);
				if(pstParseInfoTmp == NULL)
				{
					fatal("Mem failed");
				}
				if(pstConn->ucData)
				{
					free(pstConn->ucData);
				}

				pstParseInfoTmp->dataLen = 0;
				pstConn->ucData    = pstParseInfoTmp;
				pstConn->callClose = imap_callback_hook;
				
			}
			break;
			case _SMTP_AUTH_LOGIN:
			case _SMTP_AUTH_SEND_UERNAME: 
			{
				if(resCode != SMTP_INPUT)
				{
					ret = RET_FAILED;
					break;
				}
				
				slValidLen = dispatch_crlf_data(&dataTmp[4],slDataLen);
				if(slValidLen < 0)
				{
					ret = RET_FAILED;
					goto err;
				}
				memcpy(ucStream,&dataTmp[4],slValidLen < ARRAY_SIZE(ucStream) ? slValidLen : ARRAY_SIZE(ucStream));

				base64_decode(ucStream,slValidLen,ucDecodeInfo);
				printf("Get base decode info %s \n --> %s \n",ucStream,ucDecodeInfo);
				if(_SMTP_AUTH_LOGIN == slLastStatus)
				{
					slNewStatus = _SMTP_AUTH_NEED_UERNAME;
				}
				else
				{
					slNewStatus = _SMTP_AUTH_NEED_KEY;
				}
			}
			break;
			case _SMTP_AUTH_SEND_KEY:
			{
				if(resCode != SMTP_AUTHOK)
				{
					printf("Smtp auth failed \n");
					ret = RET_FAILED;
					break;
				}
				slNewStatus = _SMTP_AUTH_END;
			}
			break;
			case _SMTP_MAIL_START:
			{
				if(resCode != SMTP_MAILOK)
				{
					printf("Smtp mail from failed \n");
					ret = RET_FAILED;
					break;
				}
				slNewStatus = _SMTP_MAIL_END;
			}
			break;
			case _SMTP_RCPT_START:
			{
				if(resCode != SMTP_MAILOK)
				{
					printf("Smtp rcpt to  failed \n");
					ret = RET_FAILED;
					break;
				}
				slNewStatus = _SMTP_RCPT_END;
			}
			break;
			case _SMTP_DATA_START:
			{
				if(resCode != SMTP_STARTMAIL)
				{
					printf("Smtp date start failed \n");
					ret = RET_FAILED;
					break;
				}
				// printf("Now need stash content \n");
				// const struct tcp_stream *const pstTcpStram = container_of(pstConn,struct tcp_stream,stConnInfo);
				// if(NULL == pstTcpStram)
				// {
				// 	ret = RET_FAILED;
				// 	goto err;
				// }
				// /*这里其实是一个起始位置*/
				// pstParseInfo->dataLen = pstTcpStram->server.count;
				// printf("Data start pos %d \n",pstParseInfo->dataLen);
				slNewStatus = _SMTP_DATA_END;
			}
			break;
			case _SMTP_TRANS_QUIT:
			{
				if(resCode != SMTP_MAILOK && resCode != SMTP_BYE)
				{
					printf("Smtp quit failed \n");
					ret = RET_FAILED;
					break;
				}
				// printf("Now need parse content \n");
				// const struct tcp_stream *const pstTcpStram = container_of(pstConn,struct tcp_stream,stConnInfo);
				// if(NULL == pstTcpStram)
				// {
				// 	ret = RET_FAILED;
				// 	goto err;
				// }
				// const char *const strEmaildata = pstTcpStram->server.data + pstParseInfo->dataLen;
				// int len = pstTcpStram->server.count - pstParseInfo->dataLen;
				printf("Now get dataLen %d \n",pstParseInfo->dataLen);
				//parse_smtp_text(pstParseInfo->ucData,pstParseInfo->dataLen,pstParseInfo);
				/*这里需要判断是否需要再次写入文件*/
				if(pstParseInfo->dataLen != 0)
				{
					write_date(pstParseInfo->strTmpFile,pstParseInfo->ucData,pstParseInfo->dataLen);
				}
				notify_email_insight(pstParseInfo,_EMAIL_SMTP,pstEthInfo->h_dest,(unsigned int)addr->daddr);
				bzero(pstParseInfo->strTmpFile,ARRAY_SIZE(pstParseInfo->strTmpFile));

				printf("Now get one email data \n");
				printf("Email User:%s \n",pstParseInfo->strSender);
				printf("Email Key :%s \n",pstParseInfo->strKey);
				printf("Email To: \n");
				
				printf(" %s; \n",pstParseInfo->strTo);
				
				printf("\n");
			}
			break;
			default:
			{
				if(pstParseInfo->dataLen != 0)
				{
					write_date(pstParseInfo->strTmpFile,pstParseInfo->ucData,pstParseInfo->dataLen);
					pstParseInfo->dataLen = 0;
					bzero(pstParseInfo->ucData,pstParseInfo->dataLen);
				}
				if(resCode != SMTP_MAILOK)
				{
					INFO("Smtp default failed resCode %d slLastStatus = %d",resCode,slLastStatus);
					ret = RET_FAILED;
					break;
				}
			}
		}
	}
	
	pstConn->slUsrType = slNewStatus;
	return ret;

err:
	pstConn->eMainType = CONN_MAIN_INVALID;
	pstConn->slUsrType = 0;
	return ret;
}

int do_insight_email(void *data,int slDataLen,int slProtocol,
	void *addr,void *pstEthInfo,int direction,void *pstConn)
{
	struct tuple4 *pstAddr = addr;
	//struct ethhdr *pstEth  = pstEthInfo;
	NIDS_CONNTRACK_RECORD *pstConnInfo = pstConn;

	if(_TARGET_SMTP == pstConnInfo->eMainType  && 
	   (   (direction == IP_CT_DIR_REPLY    &&  pstAddr->source == SMTP_PORT) 
	    || (direction == IP_CT_DIR_ORIGINAL &&  pstAddr->dest == SMTP_PORT))
	   )
	{
		return handle_smtp_protocol(data,slDataLen,slProtocol,addr,pstEthInfo,direction,pstConn);
	}
	else if(_TARGET_IMAP4 == pstConnInfo->eMainType && 
	   (   (direction == IP_CT_DIR_REPLY    &&  pstAddr->source == IAMP_PORT) 
	    || (direction == IP_CT_DIR_ORIGINAL &&  pstAddr->dest == IAMP_PORT))
	   )
	{
		return handle_imap4_protocol(data,slDataLen,slProtocol,addr,pstEthInfo,direction,pstConn);
	}
	else if(_TARGET_POP3 == pstConnInfo->eMainType && 
	   (   (direction == IP_CT_DIR_REPLY    &&  pstAddr->source == POP_PORT) 
	    || (direction == IP_CT_DIR_ORIGINAL &&  pstAddr->dest == POP_PORT))
	   )
	{
		return handle_pop_protocol(data,slDataLen,slProtocol,addr,pstEthInfo,direction,pstConn);
	}
	else
	{
		return RET_FAILED;
	}
	

}

/******************************************************************************************************************
 * 							IMAP 只从两种状态识别,均为客户端发起
 *							1.login
 *							2.UDI FETCH 										
 * ****************************************************************************************************************/

int parse_imap_text(const char * const data,int slDataLen,SMTP_PARSE_INFO *pstParseInfo)
{
	char * strFindTmp        	= NULL;
	int i = 0;
	int slTmpLen = slDataLen;

	if((strFindTmp = strstr(data,"\r\nFrom: ")) != NULL) 
	{
		sscanf(strFindTmp,"%*[^<]<%32[^>]",pstParseInfo->strSender);
	}
	else
	{
		/*作为接受报文怎么可能不存在from*/
		WARNING("Now parse recive email info but not find From");
		return RET_FAILED;
	}

	if((strFindTmp = strstr(data,"\r\nTo: ")) != NULL) 
	{
		strFindTmp += strlen("\r\nTo: ");
		if((slTmpLen = dispatch_crlf_data(strFindTmp,0)) < 0)
		{
			return RET_FAILED;
		}
		char *pstrTo = calloc(1,slTmpLen + 1);
		if(NULL == pstrTo)
		{
			return RET_FAILED;
		}
		/*这里可能存在多个to*/
		memcpy(pstrTo,strFindTmp,slTmpLen);
		slTmpLen = 0;
		char strToTmp [32] = {0};

		for(i = 0;i < MAX_RECORD_TO;i++)
		{
			bzero(strToTmp,ARRAY_SIZE(strToTmp));
			if(sscanf(pstrTo + slTmpLen,"%*[^<]<%32[^>]",strToTmp) != 1)
			{
				break;
			}
			
			strcat(pstParseInfo->strTo,strToTmp);
			strcat(pstParseInfo->strTo,";");

			strFindTmp = strstr(pstrTo,strToTmp);
			slTmpLen += (strFindTmp - pstrTo);
		}
		free(pstrTo);
	}
	
	if(parse_smtp_text(data,slDataLen,pstParseInfo) < 0)
	{
		printf("Parse imap info failed \n");
		return RET_FAILED;
	}
	return RET_SUCCESS;
}

static inline int handle_imap_stream (NIDS_CONNTRACK_RECORD *pstConn, const char *buff, size_t len)
{
	//printf("Get %s \n",buff);
	if(strstr(buff,"UID FETCH") != NULL)
	{
		char strTag[8] 		= {0};
		char strCmd[16] 	= {0};
		char strFetch[8] 	= {0};
		char strId[8]  		= {0};
		char strSession[32] = {0};
		printf("Line = %d \n",__LINE__);
		/*这里直接是获取邮件,但是回复不一定是邮件*/
		//char *strFetch = "C145 UID FETCH 121 (UID BODY.PEEK[])";
		if(sscanf(buff,"%8[^ ] %16[^ ] %8[^ ] %8[^ ]%*[^(](%32[^)]",strTag,strCmd,strFetch,strId,strSession) != 5)
		{
			return RET_FAILED;
		}
		printf("Line = %d \n",__LINE__);
		IMAP_PARSE_INFO *pstImapInfo = pstConn->ucData;
		if(pstImapInfo)
		{
			if(pstConn->slUsrType != _IMAP_LOGIN_)
			{
				free(pstConn->ucData);
				pstConn->ucData = NULL;
				pstImapInfo     = NULL;
			}	
		}
		printf("Line = %d \n",__LINE__);
		if(pstImapInfo == NULL)
		{	
			pstImapInfo = calloc(1,sizeof(IMAP_PARSE_INFO) + DEFAILT_CACHE_BUF_SIZE);
			if(pstImapInfo == NULL)
			{
				return RET_FAILED;
			}
		}

		memset(pstImapInfo->strRecordTag,0,sizeof(pstImapInfo->strRecordTag));
		strncpy(pstImapInfo->strRecordTag,strTag,ARRAY_SIZE(pstImapInfo->strRecordTag));
		strncpy(pstImapInfo->strId,strId,ARRAY_SIZE(pstImapInfo->strId));
		strncpy(pstImapInfo->strSession,strSession,ARRAY_SIZE(pstImapInfo->strSession));

		pstImapInfo->dataLen 	= 0; 
		pstConn->slUsrType 		= _IMAP_FETCH;
		pstConn->ucData    		= pstImapInfo;
		pstConn->callClose 		= imap_callback_hook;

		return RET_SUCCESS;
	}
	else if(strstr(buff,"LOGIN") != NULL)
	{
		printf("Line = %d \n",__LINE__);
		char strTag[8] = {0};
		char strCmd[16] = {0};
		char strUser[32] = {0};
		char strKey[128] = {0};

		/*解析用户名和密码*/
		//C3 LOGIN luochao@snqu.com "Luo940924"
		if(sscanf(buff,"%8[^ ] %16[^ ] %32[^ ] %128[^\r]",strTag,strCmd,strUser,strKey) != 4)
		{
			printf("Line = %d \n",__LINE__);
			return RET_FAILED;
		}
		IMAP_PARSE_INFO *pstImapInfo = calloc(1,sizeof(IMAP_PARSE_INFO) + DEFAILT_CACHE_BUF_SIZE);
		if(pstImapInfo == NULL)
		{
			return RET_FAILED;
		}
		printf("Email:%s-->Key:%s\n",strUser,strKey);
		pstImapInfo->dataLen = 0; 
		strncpy(pstImapInfo->strUser,strUser,ARRAY_SIZE(pstImapInfo->strUser));
		strncpy(pstImapInfo->strKey,strKey,ARRAY_SIZE(pstImapInfo->strKey));
		strncpy(pstImapInfo->strRecordTag,strTag,ARRAY_SIZE(pstImapInfo->strRecordTag));
		
		if(pstConn->ucData)
		{
			free(pstConn->ucData);
		}
		pstConn->slUsrType = _IMAP_LOGIN_;
		pstConn->ucData    = pstImapInfo;
		pstConn->callClose = imap_callback_hook;
		return RET_SUCCESS;
	}
	else
	{
		return RET_FAILED;
	}
		
}

int handle_imap4_protocol(void *data,int slDataLen,int slProtocol,
	struct tuple4 *addr,struct ethhdr *pstEthInfo,int direction,NIDS_CONNTRACK_RECORD *pstConn)
{
	IMAP_PARSE_INFO *pstImapInfo = pstConn->ucData;
	if(NULL == pstImapInfo)
	{
		return RET_FAILED;
	}
	
	if(direction == IP_CT_DIR_REPLY)
	{
		if(pstConn->slUsrType == _IMAP_FETCH) /*这里的数据应该都要缓存下来，并且需要查找结束标志*/
		{
			int isEnd = 0;
			char *strData = (char *)data;
			char *strFind = strData + (slDataLen - 20);  /*结束标志符在最后*/
			if(strstr(strFind,"UID FETCH Completed") == NULL) /*没有结束标志*/
			{
				if((pstImapInfo->dataLen + slDataLen) < DEFAILT_CACHE_BUF_SIZE)
				{
					memcpy(pstImapInfo->ucData + pstImapInfo->dataLen,data,slDataLen);
					pstImapInfo->dataLen += slDataLen;
					return RET_SUCCESS;
				}
			}
			else
			{
				isEnd = 1; /*可能只是end了一个*/
			}
			int fd = 0;
			/*需要写文件*/
			if(strlen(pstImapInfo->strTmpFile) != 0)
			{
				fd = open(pstImapInfo->strTmpFile,O_WRONLY|O_APPEND);
				if(fd < 0)
				{
					WARNING("Open file failed %s",pstImapInfo->strTmpFile);
					goto handle_err;
				}
			}
			else
			{	time_t nowTime = time(NULL);
				char strTimeStamp[128] = {0};
				strftime(strTimeStamp,128,"%H-%M-%S",localtime(&nowTime));

				snprintf(pstImapInfo->strTmpFile,ARRAY_SIZE(pstImapInfo->strTmpFile),"%semail_%02x%02x%02x%02x%02x%02x_%s",
				EMAIL_TMP_PATH,
				pstEthInfo->h_dest[0],pstEthInfo->h_dest[1],pstEthInfo->h_dest[2],pstEthInfo->h_dest[3],pstEthInfo->h_dest[4],pstEthInfo->h_dest[5],
				strTimeStamp);

				fd = open(pstImapInfo->strTmpFile,O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG|S_IRWXO);
				if(fd < 0)
				{
					WARNING("Open file failed %s",pstImapInfo->strTmpFile);
					goto handle_err;
				}
				//pstConn->callClose = imap_callback_hook;
			}
			
			if(write(fd,pstImapInfo->ucData,pstImapInfo->dataLen) != pstImapInfo->dataLen)
			{
				WARNING("write %d date to %s failed ",pstImapInfo->dataLen,pstImapInfo->strTmpFile);
			}
			if(write(fd,data,slDataLen) != slDataLen)
			{
				WARNING("write %d date to %s failed ",slDataLen,pstImapInfo->strTmpFile);
			}
			close(fd);

			pstImapInfo->dataLen = 0;
			memset(pstImapInfo->ucData,0,DEFAILT_CACHE_BUF_SIZE);
			
			if(isEnd)
			{
				INFO("Now  imap4 email one uid info \n"); /*可能会有多个邮件，imaps是长链接，不能等关闭，在每次接受到新的结束符之后，新开文件处理*/
				//parse_email(pstImapInfo->strTmpFile,_EMAIL_IMAP);
				notify_email_insight(pstImapInfo,_EMAIL_IMAP,pstEthInfo->h_dest,(unsigned int)addr->daddr);
				memset(pstImapInfo->strTmpFile,0,sizeof(pstImapInfo->strTmpFile));

			}
			return RET_SUCCESS;
		}
		else if(pstConn->slUsrType == _IMAP_LOGIN_) /*认证完之后不一定有邮件，但是可以先处理认证*/
		{
			//C3 OK Success login ok
			char strTag[8]  = {0};
			char strStat[8] = {0};
			if(sscanf((char *)data,"%8[^ ] %8[^ ]",strTag,strStat) != 2)
			{
				goto handle_err;
			}
			if(strcasecmp(strStat,"ok") != 0)  
			{
				goto handle_err;
			}
			/*这里应该有状态变化,让流重新进入规则匹配，获取UID FETCH*/
			pstConn->eMainType  = CONN_MAIN_INVALID;
			pstConn->eSubType  &= ~SET_STREAM_ACTION(_STREAM_GATHER_BASE);
			return RET_SUCCESS;
		}
		else
		{
			return RET_FAILED;
		}
	}
	else
	{
		return RET_SUCCESS;
	}

handle_err:
	INFO("handle_err \n");
	pstConn->eMainType  = CONN_MAIN_INVALID;
	pstConn->eSubType  &= ~SET_STREAM_ACTION(_STREAM_GATHER_BASE);
	free(pstConn->ucData);
	pstConn->ucData = NULL;
	return RET_FAILED;
	
}
int do_start_imap(void *pri)
{
	m_priv_t *pstPri = (m_priv_t *)pri;
	NIDS_CONNTRACK_RECORD *pstConn = (NIDS_CONNTRACK_RECORD *)pstPri->pstconn;
	return handle_imap_stream(pstConn,pstPri->data,pstPri->dlen);
}

/***********************************************************************************************
 * 		解析POP协议
 * 
************************************************************************************************/
int handle_pop_protocol(void *data,int slDataLen,int slProtocol,
	struct tuple4 *addr,struct ethhdr *pstEthInfo,int direction,NIDS_CONNTRACK_RECORD *pstConn)
{
	IMAP_PARSE_INFO *pstImapInfo = pstConn->ucData;
	if(NULL == pstImapInfo)
	{
		return RET_FAILED;
	}
	char *strData = data;
	
	if(direction == IP_CT_DIR_REPLY)
	{
		if(pstConn->slUsrType == _POP_RETR)
		{
			if((pstImapInfo->dataLen + slDataLen) < DEFAILT_CACHE_BUF_SIZE)
			{
				memcpy(pstImapInfo->ucData + pstImapInfo->dataLen,data,slDataLen);
				pstImapInfo->dataLen += slDataLen;
				return RET_SUCCESS;
			}

			write_date(pstImapInfo->strTmpFile,pstImapInfo->ucData,pstImapInfo->dataLen);
			write_date(pstImapInfo->strTmpFile,data,slDataLen);

			pstImapInfo->dataLen = 0;
			memset(pstImapInfo->ucData,0,DEFAILT_CACHE_BUF_SIZE);

			return RET_SUCCESS;
		}
		else if(pstConn->slUsrType == _POP_USER)
		{
			if(strncasecmp(strData,"+OK",3) != 0)
			{
				memset(pstImapInfo->strUser,0,ARRAY_SIZE(pstImapInfo->strUser));
				return RET_FAILED;
			}
			return RET_SUCCESS;
		}
		else if(pstConn->slUsrType == _POP_PASS)
		{
			if(strncasecmp(strData,"+OK",3) != 0)
			{
				memset(pstImapInfo->strKey,0,ARRAY_SIZE(pstImapInfo->strKey));
				return RET_FAILED;
			}
			return RET_SUCCESS;
		}
		else if(pstConn->slUsrType == _POP_QUIT)
		{
			if(strncasecmp(strData,"+OK",3) != 0)
			{
				return RET_FAILED;
			}
			return RET_SUCCESS;
		}
		else
		{
			return RET_SUCCESS;
		}

	}
	else if(direction == IP_CT_DIR_ORIGINAL)
	{
		int i = 0;
		int eNewStat = _POP_UNKNWN;
		for(i = 0;i < ARRAY_SIZE(stPOPCmdStatus);i++)
		{
			if(strncasecmp(strData,stPOPCmdStatus[i].strCmdBuf,strlen(stPOPCmdStatus[i].strCmdBuf)) == 0)
			{
				eNewStat = stPOPCmdStatus[i].eCmdStatus;
				break;
			}
		}
		if(eNewStat == _POP_USER)
		{
			char strUser[32] = {0};
			sscanf(strData,"%*[^ ] %32[^\r]",strUser);
			INFO("Get pop user-->%s",strUser);
			strncpy(pstImapInfo->strUser,strUser,ARRAY_SIZE(pstImapInfo->strUser));
		}
		else if(eNewStat == _POP_PASS)
		{
			char strKey[128] = {0};
			sscanf(strData,"%*[^ ] %128[^\r]",strKey);
			INFO("Get pop key-->%s",strKey);
			strncpy(pstImapInfo->strKey,strKey,ARRAY_SIZE(pstImapInfo->strKey));
		}
		else if(eNewStat == _POP_RETR)
		{
			/*每个retr表示一个邮件请求*/
			if(strlen(pstImapInfo->strTmpFile) != 0)
			{
				if(pstImapInfo->dataLen != 0)
				{
					write_date(pstImapInfo->strTmpFile,pstImapInfo->ucData,pstImapInfo->dataLen);
					pstImapInfo->dataLen = 0;
					memset(pstImapInfo->ucData,0,DEFAILT_CACHE_BUF_SIZE);
				}
				INFO("Now need parse pop email info %s ",pstImapInfo->strTmpFile);
				//parse_email(pstImapInfo->strTmpFile,_EMAIL_POP3);
				notify_email_insight(pstImapInfo,_EMAIL_POP3,pstEthInfo->h_source,(unsigned int)addr->saddr);
				/*这需要先解析一次*/
				bzero(pstImapInfo->strTmpFile,ARRAY_SIZE(pstImapInfo->strTmpFile));
			}
			time_t nowTime = time(NULL);
			char strTimeStamp[128] = {0};
			strftime(strTimeStamp,128,"%H-%M-%S",localtime(&nowTime));

			snprintf(pstImapInfo->strTmpFile,ARRAY_SIZE(pstImapInfo->strTmpFile),"%semail_%02x%02x%02x%02x%02x%02x_%s",
			EMAIL_TMP_PATH,
			pstEthInfo->h_dest[0],pstEthInfo->h_dest[1],pstEthInfo->h_dest[2],pstEthInfo->h_dest[3],pstEthInfo->h_dest[4],pstEthInfo->h_dest[5],
			strTimeStamp);


		}
		else if(eNewStat == _POP_QUIT)
		{
			if(pstConn->slUsrType != _POP_RETR) /*有可能只是认证*/
				return RET_SUCCESS;

			if(pstImapInfo->dataLen != 0)
			{
				write_date(pstImapInfo->strTmpFile,pstImapInfo->ucData,pstImapInfo->dataLen);
				pstImapInfo->dataLen = 0;
				memset(pstImapInfo->ucData,0,DEFAILT_CACHE_BUF_SIZE);
			}
			/**/
			INFO("Now need parse pop email info %s",pstImapInfo->strTmpFile);
			//return parse_email(pstImapInfo->strTmpFile,_EMAIL_POP3);
			notify_email_insight(pstImapInfo,_EMAIL_POP3,pstEthInfo->h_source,(unsigned int)addr->saddr);
			bzero(pstImapInfo->strTmpFile,ARRAY_SIZE(pstImapInfo->strTmpFile));
			return RET_SUCCESS;
		}
		else
		{

		}
		pstConn->slUsrType = eNewStat;
		return RET_SUCCESS;
	}
	else
	{
		return RET_FAILED;
	}

}
static inline int handle_pop_stream (NIDS_CONNTRACK_RECORD *pstConn, const char *buff, size_t len)
{
		//printf("Get %s \n",buff);
	if(strncasecmp(buff,"USER",strlen("USER")) == 0)
	{
		char strUser[32] = {0};
		sscanf(buff,"%*[^ ] %32[^\r]",strUser);

		printf("Line = %d \n",__LINE__);
		IMAP_PARSE_INFO *pstImapInfo = pstConn->ucData;
		if(pstImapInfo)
		{
			free(pstConn->ucData);
			pstConn->ucData = NULL;
			pstImapInfo     = NULL;	
		}

		if(pstImapInfo == NULL)
		{	
			pstImapInfo = calloc(1,sizeof(IMAP_PARSE_INFO) + DEFAILT_CACHE_BUF_SIZE);
			if(pstImapInfo == NULL)
			{
				return RET_FAILED;
			}
		}

		memset(pstImapInfo,0,sizeof(IMAP_PARSE_INFO));
		strncpy(pstImapInfo->strUser,strUser,ARRAY_SIZE(pstImapInfo->strUser));
		
		pstImapInfo->dataLen 	= 0; 
		pstConn->slUsrType 		= _POP_USER;
		pstConn->ucData    		= pstImapInfo;
		pstConn->callClose      = imap_callback_hook;

		return RET_SUCCESS;
	}
	else if(strncasecmp(buff,"RETR",strlen("RETR")) == 0)
	{
		IMAP_PARSE_INFO *pstImapInfo = pstConn->ucData;
		if(pstImapInfo)
		{
			if(pstConn->slUsrType != _POP_PASS)
			{
				free(pstConn->ucData);
				pstConn->ucData = NULL;
				pstImapInfo     = NULL;	
			}
		}

		if(pstImapInfo == NULL)
		{	
			pstImapInfo = calloc(1,sizeof(IMAP_PARSE_INFO) + DEFAILT_CACHE_BUF_SIZE);
			if(pstImapInfo == NULL)
			{
				return RET_FAILED;
			}
		}

		pstImapInfo->dataLen 	= 0; 
		pstConn->slUsrType 		= _POP_RETR;
		pstConn->ucData    		= pstImapInfo;
		pstConn->callClose      = imap_callback_hook;
		return RET_SUCCESS;
	}
	else
	{
		return RET_FAILED;
	}
}

int do_start_pop(void *pri)
{
	m_priv_t *pstPri = (m_priv_t *)pri;
	NIDS_CONNTRACK_RECORD *pstConn = (NIDS_CONNTRACK_RECORD *)pstPri->pstconn;
	return handle_pop_stream(pstConn,pstPri->data,pstPri->dlen);
}

int get_email_data(const char *strFileName,unsigned char **p,unsigned int *len)
{
    if(access(strFileName,R_OK) != 0)
    {
        printf("No input data \n");
        return RET_FILEERR;
    }
    struct stat stFileInfo;
    memset(&stFileInfo,0,sizeof(stFileInfo));

    if (stat(strFileName, &stFileInfo) < 0) 
    {
        return RET_FILEERR;
    }

    unsigned char *ucFileData = (unsigned char *)calloc(1,stFileInfo.st_size + 128);
    if(ucFileData == NULL)
    {
        return RET_FILEERR;
    }
    bzero(ucFileData,stFileInfo.st_size + 128);

    int fd = open(strFileName,O_RDONLY);
    if(fd < 0)
    {
        free(ucFileData);
        return RET_FILEERR;
    }
    read(fd,ucFileData,stFileInfo.st_size);
    close(fd);

    *p   = ucFileData;
    *len = stFileInfo.st_size;

    return RET_SUCCESS;
}


int parse_email(char *strFileName,ENUM_EMAIL_TYPE type,void *pstEmail)
{
    int ret = 0;
    unsigned int   ulFileLen = 0;
    unsigned char *ucFileData = NULL;
    // SMTP_PARSE_INFO stEmailInfo;
    // bzero(&stEmailInfo,sizeof(stEmailInfo));


    if(get_email_data(strFileName,&ucFileData,&ulFileLen) < 0 || ulFileLen < 30)
    {
        printf("Get file err \n");
		return RET_FAILED;
    }
    printf("Read file size %u \n",ulFileLen);
	if(_EMAIL_SMTP == type)
	{
		ret = parse_smtp_text((const char *)ucFileData,ulFileLen,pstEmail);
	}
	else //if(_EMAIL_IMAP == type)
	{
		ret = parse_imap_text((const char *)ucFileData,ulFileLen,pstEmail);
	}
	// else
	// {
	// 	ret = parse_smtp_text((const char *)ucFileData,ulFileLen,pstEmail);
	// }
    free(ucFileData);

    return ret;
}

