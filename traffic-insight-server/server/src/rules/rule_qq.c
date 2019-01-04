/*
 * @Author: jiamu 
 * @Date: 2018-10-10 19:50:15 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-19 16:14:33
 */

#include "rule_qq.h"
#include "protocol.h"

typedef struct _msg_qq {
	uint8_t	    flag;
	uint16_t	ver;
	uint16_t	cmd;
	uint16_t	seq;
	unsigned int num;
} __attribute__((packed)) msg_qq_t;

#define QQ_FLAG			(0x02)
#define QQ_VER			(0x3649)
#define QQ_VER1			(0x3625)
#define QQ_ENTRY_NUM	(64)
#define QQ_SIZE			(4)
#define QQ_SND_CYCLE	(HZ << 5) /* 32s */
#define QQ_BUF_SIZE		(QQ_ENTRY_NUM * QQ_SIZE)
#define QQ_MSGSIZE_MIN	(sizeof(msg_qq_t) + sizeof(uint32_t))
#define QQM_SIZE_MAX    16
#define QQM_SIZE_MIN    5
static int    slInitFlg  = 0;
static int    slEntryNum = 0;
static struct list_head msglist;

typedef struct oicq_command
{
	unsigned short usCmd;
	const char *const strDesc;
}OICQ_CMD;

static const OICQ_CMD oicq_command_vals[] = {
	{ 0x0001,	"Log out" },
	{ 0x0002,	"Heart Message" },
	{ 0x0004,	"Update User information" },
	{ 0x0005,	"Search user" },
	{ 0x0006,	"Get User informationBroadcast" },
	{ 0x0009,	"Add friend no auth" },
	{ 0x000a,	"Delete user" },
	{ 0x000b,	"Add friend by auth" },
	{ 0x000d,	"Set status" },
	{ 0x0012,	"Confirmation of receiving message from server" },
	{ 0x0016,	"Send message" },
	{ 0x0017,	"Receive message" },
	{ 0x0018,	"Retrieve information" },
	{ 0x001a,	"Reserved " },
	{ 0x001c,	"Delete Me" },
	{ 0x001d,	"Request KEY" },
	{ 0x0021,	"Cell Phone" },
	{ 0x0022,	"Log in" },
	{ 0x0026,	"Get friend list" },
	{ 0x0027,	"Get friend online" },
	{ 0x0029,	"Cell PHONE" },
	{ 0x0030,	"Operation on group" },
	{ 0x0031,	"Log in test" },
	{ 0x003c,	"Group name operation" },
	{ 0x003d,	"Upload group friend" },
	{ 0x003e,	"MEMO Operation" },
	{ 0x0058,	"Download group friend" },
	{ 0x005c,	"Get level" },
	{ 0x0062,	"Request login" },
	{ 0x0065,	"Request extra information" },
	{ 0x0067,	"Signature operation" },
	{ 0x0080,	"Receive system message" },
	{ 0x0081,	"Get status of friend" },
	{ 0x00b5,	"Get friend's status of group" },
	{ 0,			NULL }
};
static int slHeart = 0;
static inline int check_is_oicq(msg_qq_t *msg)
{
	int i = 0;
	unsigned short cmd = htons(msg->cmd);
	
	while(oicq_command_vals[i].strDesc)
	{
		i++;
		if(cmd == oicq_command_vals[i].usCmd)
		{
			return RET_SUCCESS;
		}
	}

	return RET_FAILED;
}

static int do_qq_action(int actionType,void *data)
{
	// if(0 == slInitFlg)
	// {
	// 	init_list_head(&msglist);
	// }
	
    m_priv_t *pstPri = (m_priv_t*)data;
	//printf("Now get one qq data stream  !!!!!!!\n");
    uint32_t num = 0;
	char buf[QQM_SIZE_MAX + 1] = {0};

	msg_qq_t *msg	= (msg_qq_t *)pstPri->data;
	
	if(pstPri->dlen >= QQ_MSGSIZE_MIN && msg->flag == QQ_FLAG &&
		(msg->ver != htons(QQ_VER) || msg->ver != htons(QQ_VER1)) &&
		check_is_oicq(msg) == RET_SUCCESS)
    {
			//num = *(uint32_t *)msg->data;
			num = msg->num;
			num = htonl(num);
			snprintf(buf,QQM_SIZE_MAX,"%u",num);
			do_record_data(buf,strlen(buf),pstPri);
			// printf("QQ message--> size:%d buf:%s  \n",strlen(buf),buf);
			// write_date("/tmp/qqtest",pstPri->data,pstPri->dlen);
			// write_date("/tmp/qqtest","\r\n********\r\n",10);
			// pstPri->ptl->msg.mc_add(pstPri->ptl, QQ
			// 			, buf, strlen(buf), ip, mac);
			return RET_SUCCESS;
	}
    else if (pstPri->prd) 
    {
		#if 0
		int			size = 0;
		const char	*ptr = NULL;
		ptr = pstPri->prd;
		if(*ptr <=0x30 && *ptr >= 0x39)
			return -1;
		while (*ptr >=0x30 && *ptr <= 0x39 && size < QQM_SIZE_MAX && ptr < pstPri->end)
        {
            ptr++, size++;
        }
		
		if (size && size <= QQM_SIZE_MAX && size >= QQM_SIZE_MIN) 
        {
			/**
			 * @brief 
			 * 这里可能有问题,qq号有时获取出来是错误的,
			 * 原来protolistzk也是一样的错误
			 */
			memcpy(buf,pstPri->prd,size);	
			do_record_data(buf,strlen(buf),pstPri);
			printf("QQ message(prd)--> size:%d prd:%s  %02x-%02x-%02x-%02x \n",size,buf,pstPri->prd[0],pstPri->prd[1],pstPri->prd[2],pstPri->prd[3]);
			// pstPri->ptl->msg.mc_add(pstPri->ptl, QQ
			// 			, pstPri->prd, size, ip, mac);
			write_date("/tmp/qqtest",pstPri->data,pstPri->dlen);
			write_date("/tmp/qqtest","\r\n********\r\n",10);
			printf("QQ message--> size:%d info:%s  \n",size,pstPri->prd);
			return RET_SUCCESS;
		}
		#else
		unsigned char *ucMatchData = (unsigned char *)pstPri->prd;
		unsigned char ucNumLen 	   = *ucMatchData++;
		INFO("Now get  qq numlen %d ",ucNumLen);
		if((ucNumLen < (QQM_SIZE_MIN + 4)) || (ucNumLen > (QQM_SIZE_MAX + 4)))
		{
			return RET_FAILED;
		}
		ucNumLen -= 4;
		memcpy(buf,ucMatchData,ucNumLen);
		print("QQ num is %s \n",buf);
		if(_is_all_digit(buf, strlen(buf), QQM_SIZE_MAX))
		{
			return do_record_data(buf,strlen(buf),pstPri);
		}
		return RET_FAILED;
		#endif
	}

	return RET_FAILED;

}

static int do_qq_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stQQCtrlInfo = {
    .strName        = "QQ",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_qq_action,
    .cbProtoPack    = do_qq_pack,
    .private        = NULL
};