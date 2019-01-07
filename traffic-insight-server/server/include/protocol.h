/*
 * @Author: jiamu 
 * @Date: 2018-10-08 15:40:34 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-19 16:10:52
 */



#ifndef _SNORT_POROTOCOL_H_
#define _SNORT_POROTOCOL_H_
#include "im_config.h"
#include "log.h"
#include "snort_file.h"

typedef int (*protoAction)(int actionType,void *data);
typedef int (*protoGetMsg)(void *buf,int slDataLen);          //get row message info 
typedef int (*protoPack)(void *buf,int slBufLen);            //pack row massage in buf by special format to upload

typedef struct
{
    char strName[64];
    int  slMsgNum;
    protoAction  cbProtoHandle;
    protoPack    cbProtoPack;
    void *private;                                       //reserve to insight data stream
}PROTOCOL_CONTORL_INFO;

typedef struct {
	//ptlt_t 			*ptl;
	unsigned int	*ret;	/* return value for netfilter hooks */
	void			*skb;	/* socket buffer contain data and contrack info,etc.  */
	char			*data;	/* position of transport layer data. */
	char			*end;	/* end of transport layer data. */
	char			*doe_ptr;
	int				dlen;	/* data len of transport layer data.  */
	int				offset; /* match pos offset the begin of data. */
	void			*pstRuleDetail;
	struct tuple4	 ht;
    struct ethhdr    stEthInfo;
	int              slDir;    //data stream direction
	const char		*prd;
	void 			*pstconn;
} m_priv_t;

typedef struct
{
	
}PROTOCOL_BASE_RECORD;

extern int ConvertNativeToAscii(char *dest, int destSize, const char *src, int srcSize);
extern int ConvertUrlToAscii(char *dest, int destSize, const char *src, int srcSize);
extern int do_record_data(void *data,int len,void *pri);

#endif
