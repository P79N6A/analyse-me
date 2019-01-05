/*
 * @Author: jiamu 
 * @Date: 2018-10-17 20:03:10 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-15 18:15:33
 */

#include "record_data.h"
#include "protocol.h"
#include "record_db.h"

#ifndef TRAFFIC_CMCC
#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#endif

#include "cJSON.h"
#include "snort_http.h"
#include "ipc.h"
#include "snort_email.h"

#define INSIGHT_OBJ_NAME        "traffic-insight"
#define TERMINAL_OVERTIME    (5 * 60 * 60)
#define TERMINAL_HASH_SIZE   128
#define RECORD_UPDATE_TIME   5
#define TIME_5_HOURS         (5 * 60 * 60)


static int slUseDataBase = 1;
//static int virtual_ubus_init(struct ev_loop *loop);
static void record_data_cb(struct ev_loop *loop, ev_timer *watcher, int revents);

#ifndef TRAFFIC_CMCC
static struct blob_buf ubusMsg;
static int ubus_log(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg);

static int virtual_get_req(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg);
static int virtual_get_url(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg);
static int virtual_get_email(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg);
#endif

static ev_io    ubus_watcher;
static ev_timer tm_watcher;
static struct ubus_context *gctx;

static struct list_head stTerminal[TERMINAL_HASH_SIZE];

#ifndef TRAFFIC_CMCC
enum {
	LOG_ENABLE = 0,
	__LOG_MAX
};
enum {
	_REQ_INFO,
	_REQ_MAX,
};

enum {
	_URL_INFO,
	_URL_MAX,
};
enum {
	_EMAIL_INFO,
	_EMAIL_MAX,
};
static const struct blobmsg_policy log_policy[] = {
	[LOG_ENABLE] = { .name = "enable", .type = BLOBMSG_TYPE_BOOL },
};
static const struct blobmsg_policy req_policy[] = {
	[_REQ_INFO] 	 = { .name = "req", .type    = BLOBMSG_TYPE_TABLE }, 
};
static const struct blobmsg_policy url_policy[] = {
	[_URL_INFO] 	 = { .name = "url", .type    = BLOBMSG_TYPE_TABLE }, 
};
static const struct blobmsg_policy email_policy[] = {
	[_EMAIL_INFO] 	 = { .name = "email", .type    = BLOBMSG_TYPE_TABLE }, 
};
static const struct ubus_method virtual_methods[] = {
	UBUS_METHOD("log",  ubus_log,   		log_policy),
	UBUS_METHOD("req",  virtual_get_req,  	req_policy),
	UBUS_METHOD("url",  virtual_get_url,  	url_policy),
	UBUS_METHOD("email", virtual_get_email,  	email_policy),
};

static struct ubus_object_type virtual_object_type =
	UBUS_OBJECT_TYPE(INSIGHT_OBJ_NAME, virtual_methods);

static struct ubus_object stVirtualObj = {
    .name = INSIGHT_OBJ_NAME,
    .type = &virtual_object_type,
	.methods = virtual_methods,
	.n_methods = ARRAY_SIZE(virtual_methods)
};
/**
 * @brief 
 * 这里是用于其他客户端主动发起请求的信息
 */
enum 
{
	_REQ_TERM_MAC,
	_REQ_TERM_IP,
	_REQ_TERM_TYPE,
	_REQ_TERM_VAL,
	_REQ_TERM_ONLINE_START_DATE,
	_REQ_TERM_ONLINE_START_TIME,
	_REQ_TERM_ONLINE_END_DATE,
	_REQ_TERM_ONLINE_END_TIME,
	_REQ_TERM_ACTIVE_START_DATE,
	_REQ_TERM_ACTIVE_START_TIME,
	_REQ_TERM_ACTIVE_END_DATE,
	_REQ_TERM_ACTIVE_END_TIME,
	_REQ_TERM_START_INDEX,
	_REQ_TERM_MAX,
};

static const struct blobmsg_policy req_info_policy[] = {
	[_REQ_TERM_MAC] 				= { .name = "mac", 			.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_IP] 					= { .name = "ip", 			.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_TYPE] 				= { .name = "type", 		.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_VAL] 				= { .name = "value", 		.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_ONLINE_START_DATE] 	= { .name = "olinesdate", 	.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_ONLINE_START_TIME] 	= { .name = "olinestime", 	.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_ONLINE_END_DATE] 	= { .name = "olineedate", 	.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_ONLINE_END_TIME] 	= { .name = "olineetime", 	.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_ACTIVE_START_DATE] 	= { .name = "activesdate", 	.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_ACTIVE_START_TIME] 	= { .name = "activestime", 	.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_ACTIVE_END_DATE] 	= { .name = "activeedate", 	.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_ACTIVE_END_TIME] 	= { .name = "activeetime", 	.type = BLOBMSG_TYPE_STRING},
	[_REQ_TERM_START_INDEX] 		= { .name = "index", 		.type = BLOBMSG_TYPE_INT32},
	//[_REQ_TERM_LOG_EN] 				= { .name = "logen", 		.type = BLOBMSG_TYPE_INT32},
};


/**
 * @brief 
 * 	这里是用于广播消息，与客户端同步
 */
enum {
	_TREMINAL_COUNT,
	_TREMINAL_BROAD,
	_TREMINAL_URL,
	_TREMINAL_EMAIL,
	_TREMINAL_MAX
};

static const struct blobmsg_policy term_broad_policy[] = {
	[_TREMINAL_COUNT] = { .name = "count", .type = BLOBMSG_TYPE_INT32},
	[_TREMINAL_BROAD] = { .name = "data", .type = BLOBMSG_TYPE_ARRAY},
	[_TREMINAL_URL]   = { .name = "url", .type = BLOBMSG_TYPE_ARRAY},
	[_TREMINAL_EMAIL]   = { .name = "email", .type = BLOBMSG_TYPE_ARRAY},
};

enum {
	_TREMINAL_INFO_MAC,
	_TREMINAL_INFO_IP,
	_TREMINAL_INFO_ONLINE,
	_TREMINAL_INFO_ACTIVE,
	_TREMINAL_INFO_NUM,
	_TREMINAL_INFO_TYPE,
	_TREMINAL_INFO_VALUE,
	_TREMINAL_INFO_MAX_TYPE
};

static const struct blobmsg_policy term_info_policy[] = {
	[_TREMINAL_INFO_MAC] 	= { .name = "mac", 		.type = BLOBMSG_TYPE_STRING},
	[_TREMINAL_INFO_IP] 	= { .name = "ip", 		.type = BLOBMSG_TYPE_STRING},
	[_TREMINAL_INFO_ONLINE] = { .name = "oline", 	.type = BLOBMSG_TYPE_STRING},
	[_TREMINAL_INFO_ACTIVE] = { .name = "active", 	.type = BLOBMSG_TYPE_STRING},
	[_TREMINAL_INFO_NUM] 	= { .name = "num", 		.type = BLOBMSG_TYPE_INT32},
	[_TREMINAL_INFO_TYPE] 	= { .name = "type", 	.type = BLOBMSG_TYPE_STRING},
	[_TREMINAL_INFO_VALUE] 	= { .name = "value", 	.type = BLOBMSG_TYPE_STRING},
};

enum
{
	_EMAIL_INFO_MAC,
	_EMAIL_INFO_IP,
	_EMAIL_INFO_ONLINE,
	_EMAIL_INFO_ACCOUNT,
	_EMAIL_INFO_KEY,
	_EMAIL_INFO_DIRECTION,
	_EMAIL_INFO_FROM,
	_EMAIL_INFO_TO,
	_EMAIL_INFO_SUBJECT,
	_EMAIL_INFO_CONTENT,
	_EMAIL_INFO_ATTACH,
	_EMAIL_INFO_MAX
};

static const struct blobmsg_policy term_email_policy[] = {
	[_EMAIL_INFO_MAC] 		= { .name = "mac", 		.type = BLOBMSG_TYPE_STRING},
	[_EMAIL_INFO_IP] 		= { .name = "ip", 		.type = BLOBMSG_TYPE_STRING},
	[_EMAIL_INFO_ONLINE] 	= { .name = "oline", 	.type = BLOBMSG_TYPE_STRING},
	[_EMAIL_INFO_ACCOUNT] 	= { .name = "account", 	.type = BLOBMSG_TYPE_STRING},
	[_EMAIL_INFO_KEY] 		= { .name = "key", 		.type = BLOBMSG_TYPE_STRING},
	[_EMAIL_INFO_DIRECTION] = { .name = "dir", 		.type = BLOBMSG_TYPE_STRING},
	[_EMAIL_INFO_FROM] 		= { .name = "from", 	.type = BLOBMSG_TYPE_STRING},
	[_EMAIL_INFO_TO] 		= { .name = "to", 		.type = BLOBMSG_TYPE_STRING},
	[_EMAIL_INFO_SUBJECT] 	= { .name = "subject", 	.type = BLOBMSG_TYPE_STRING},
	[_EMAIL_INFO_CONTENT] 	= { .name = "content", 	.type = BLOBMSG_TYPE_STRING},
	[_EMAIL_INFO_ATTACH] 	= { .name = "attach", 	.type = BLOBMSG_TYPE_STRING},
};

#endif
          
int record_init(struct ev_loop *loop)
{
    int i = 0;

    for(i = 0;i < TERMINAL_HASH_SIZE;i++)
    {
        init_list_head(&stTerminal[i]);
    } 

	char strCmd[128] = {0};
	snprintf(strCmd,ARRAY_SIZE(strCmd),"mkdir -p %s ",ATTACH_SAVE_PATH);
	system(strCmd);

	bzero(strCmd,ARRAY_SIZE(strCmd));
	snprintf(strCmd,ARRAY_SIZE(strCmd),"mkdir -p %s ",EMAIL_TMP_PATH);
	system(strCmd);

	// virtual_db_init();

	// virtual_ubus_init(loop);

    ev_timer_init(&tm_watcher, record_data_cb, 0, RECORD_UPDATE_TIME);
	ev_timer_start(loop, &tm_watcher);
    
    return RET_SUCCESS;
}


static void ev_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	#ifndef TRAFFIC_CMCC
	struct ubus_context *ctx = (struct ubus_context *)w->data;
	ubus_handle_event(ctx);
	#endif
}

/**
 * @brief 
 * 	这里是外部应用主动请求
 * @param loop 
 * @return int 
 */
int virtual_ubus_init(struct ev_loop *loop)
{
	#ifndef TRAFFIC_CMCC
    int ret = RET_FAILED;
	gctx = ubus_connect(NULL);
	if (!gctx) {
		fatal("Failed to connect to ubus");
		return ret;
	}

	ret = ubus_add_object(gctx, &stVirtualObj);
	if (ret) {
		fatal("Failed to add object: %s", ubus_strerror(ret));
	}

    ubus_watcher.data = gctx;
    setnonblocking(gctx->sock.fd);
    ev_io_init(&ubus_watcher, ev_read_cb, gctx->sock.fd, EV_READ);
	ev_io_start(loop, &ubus_watcher);
	#endif

    return RET_SUCCESS;
}
#ifndef TRAFFIC_CMCC
static int do_create_ubusmsg(const unsigned char *ucMacAddr,uint32_t ulIp,char * onlineTime,char * activeTime,
							 ACCOUNT_TYPE_INFO *pstAccountInfo,struct blob_buf *buf)
{
	void *tbl;		
	char strBuf[128] = {0};
	snprintf(strBuf,128,"%02x:%02x:%02x:%02x:%02x:%02x",
	ucMacAddr[0],ucMacAddr[1],ucMacAddr[2],
	ucMacAddr[3],ucMacAddr[4],ucMacAddr[5]);

	ulIp = htonl(ulIp);
	tbl = blobmsg_open_table(buf, NULL);
	blobmsg_add_string(buf, term_info_policy[_TREMINAL_INFO_MAC].name, strBuf);
	blobmsg_add_string(buf,  term_info_policy[_TREMINAL_INFO_IP].name, int_ntoa(ulIp));
	blobmsg_add_string(buf,term_info_policy[_TREMINAL_INFO_ONLINE].name, onlineTime);
	blobmsg_add_string(buf,term_info_policy[_TREMINAL_INFO_ACTIVE].name, activeTime);
	blobmsg_add_u32(buf,term_info_policy[_TREMINAL_INFO_NUM].name, pstAccountInfo->num);
	blobmsg_add_string(buf,term_info_policy[_TREMINAL_INFO_TYPE].name, pstAccountInfo->strType); 
	blobmsg_add_string(buf,term_info_policy[_TREMINAL_INFO_VALUE].name, pstAccountInfo->value);
	blobmsg_close_table(buf, tbl);

	return RET_SUCCESS;
}
/**
 * @brief 
 * 	更新数据库方法
 *  1.每天更新每天的，从凌晨00:00开始记录新的数据
 *   不管相同的mac是否之前有过记录，即将此时间点
 *   作为必要过滤条件
 * 2.在数据超时时间后需要删除数据库,不用每次判断超时
 *   超时时间是一个粗粒度值，所以使用slUpdataNum在一个次数后判断
 * 3.在有数据库的版本中，每次更新数据库之后即删除缓存数据
 * 4.有相同类型账号的记录在一条中，比如两个qq
 *  记录方式为num++，然后value值为value += new
 * @param pstTerminal 
 * @return int 
 */
static int do_update_datebase(const TERM_RECORD_INFO *pstOptionTmp,struct blob_buf *buf)
{
	int j = 0,flag = 0;
	static int slUpdataNum = 0;
	ACCOUNT_TYPE_INFO stAccountInfo;
	DATA_RECORD_INFO *pstDataTmp   = NULL;
	DATA_RECORD_INFO *pstDataPos   = NULL;
	DATABASE_RECORD_ENTRY stUpdateEntry;

	slUpdataNum++;
	bzero(&stAccountInfo,sizeof(stAccountInfo));
	bzero(&stUpdateEntry,sizeof(stUpdateEntry));
	
	/**
	 * @brief 
	 *  将需要的数据全部记录到缓存中，一次性刷入数据库
	 * 	这里需要删除对应的taget
	 *  
	 */
	for(j = 0;j < _TARGET_MAX;j++)
	{
		flag = 0;
		if(pstOptionTmp->pstDataRecord[j])
		{
			bzero(&stAccountInfo,sizeof(stAccountInfo));
			bzero(&stUpdateEntry,sizeof(stUpdateEntry));

			pstDataPos = pstDataTmp = pstOptionTmp->pstDataRecord[j];
			strcpy(stAccountInfo.strType,pstDataPos->strTypeName);
			do
			{
				if(flag)
				{
					strcat(stAccountInfo.value,"+");
				}
				stAccountInfo.num++;
				strcat(stAccountInfo.value,(char *)pstDataPos->ucData);
				pstDataTmp = pstDataPos->nextaccout;
				free(pstDataPos);
				pstDataPos = pstDataTmp;
				flag = 1;
			}while(pstDataPos);
			do_update_terminal(pstOptionTmp,&stAccountInfo,&stUpdateEntry);
			do_create_ubusmsg(pstOptionTmp->ucMacAddr,pstOptionTmp->ulIPAddr,
			stUpdateEntry.strOnlineTime,stUpdateEntry.strActiveTime,&stAccountInfo,buf);
		}
	}


	
	

	if((slUpdataNum * RECORD_UPDATE_TIME ) < TIME_5_HOURS)
		return RET_SUCCESS;
	INFO("Now need update database and check if here need delete overtime dev");

	slUpdataNum = 0;
	
	return RET_SUCCESS;
}
#endif
static int do_create_virtual_notify(const TERM_RECORD_INFO *pstOptionTmp,IPC_DATA_TYPE *buf)
{
	int j = 0,flag = 0;
	int index = 0;
	int slMaxdataNum =  DEFAULT_INSIGHT_SIZE / sizeof(VIRTUAL_IPC_DATA);
	
	VIRTUAL_IPC_DATA *pstIpcData = (VIRTUAL_IPC_DATA *)buf->ucData;
	
	//ACCOUNT_TYPE_INFO *pstAccountInfo = (ACCOUNT_TYPE_INFO *)buf->ucData;
	DATA_RECORD_INFO *pstDataTmp   = NULL;
	DATA_RECORD_INFO *pstDataPos   = NULL;
	
	
	/**
	 * @brief 
	 *  将需要的数据全部记录到缓存中，一次性刷入数据库
	 * 	这里需要删除对应的taget
	 *  
	 */
	for(j = 0;j < _TARGET_MAX;j++)
	{
		flag = 0;
		if(pstOptionTmp->pstDataRecord[j])
		{
			pstDataPos = pstDataTmp = pstOptionTmp->pstDataRecord[j];
			strcpy(pstIpcData[index].stAccountInfo.strType,pstDataPos->strTypeName);
			do
			{
				if(flag)
				{
					strcat(pstIpcData[index].stAccountInfo.value,"+");
				}
				pstIpcData[index].stAccountInfo.num++;
				strcat(pstIpcData[index].stAccountInfo.value,(char *)pstDataPos->ucData);
				pstDataTmp = pstDataPos->nextaccout;
				//free(pstDataPos);
				pstDataPos = pstDataTmp;
				flag = 1;
			}while(pstDataPos);
			pstIpcData[index].ulIp = pstOptionTmp->ulIPAddr;
			memcpy(pstIpcData[index].ucMac,pstOptionTmp->ucMacAddr,6);

			index++;
			if(index == slMaxdataNum)
			{
				buf->slDataLen = index * sizeof(VIRTUAL_IPC_DATA);
				notify_insight_data(buf);

				index = 0;
				buf->slDataLen = 0;
				memset(buf->ucData,0,DEFAULT_INSIGHT_SIZE);
			}
		}
	}
	
	if(index != 0)
	{
		buf->slDataLen = index * sizeof(VIRTUAL_IPC_DATA);
		notify_insight_data(buf);

		index = 0;
		buf->slDataLen = 0;
		memset(buf->ucData,0,DEFAULT_INSIGHT_SIZE);
	}
	return RET_SUCCESS;
}
static inline void free_terminal(TERM_RECORD_INFO *pstTerminal)
{
	int i = 0,j = 0;
	DATA_RECORD_INFO *pos = NULL,*tmp = NULL;
	for(i = 0;i < _TARGET_MAX;i++)
	{
		if(pstTerminal->pstDataRecord[i] == NULL)
		{
			continue;
		}
		tmp = NULL;
		pos = pstTerminal->pstDataRecord[i];
		do
		{
			tmp = pos->nextaccout;
			free(pos);
			pos = tmp;
		}while(pos);
	}
	free(pstTerminal);
}

/**
 * @brief 
 *  此处更新全部内存数据到数据库中
 *  并且创建ubus消息
 *  消息创建完毕之后释放全部缓存
 * 这是否应该区分是否加载数据库进行处理???
 * @param loop 
 * @param watcher 
 * @param revents 
 */
static void record_data_cb(struct ev_loop *loop, ev_timer *watcher, int revents)
{
	
	int i = 0,slDataAccount = 0;
	TERM_RECORD_INFO *pstOptionTmp = NULL;
    TERM_RECORD_INFO *pstOptionPos = NULL;

	#if 0
	void *array;

	
	/**
	 * @brief Construct a new do update datebase object
	 * 先将全部数据刷入数据库
	 */
	blob_buf_init(&ubusMsg, 0);
	array = blobmsg_open_array(&ubusMsg, term_broad_policy[_TREMINAL_BROAD].name);

	for(i = 0;i < TERMINAL_HASH_SIZE;i++)
	{
		if(list_empty(&stTerminal[i]) )
		{
			continue;
		}
		list_for_each_entry_safe(pstOptionTmp,pstOptionPos,&stTerminal[i],listTerm)
		{
			do_update_datebase(pstOptionTmp,&ubusMsg);
			slDataAccount++;
			list_del(&pstOptionTmp->listTerm);
			free(pstOptionTmp);
		}
	}
	blobmsg_close_array(&ubusMsg, array);
	blobmsg_add_u32(&ubusMsg, term_broad_policy[_TREMINAL_COUNT].name, slDataAccount);
	
	/**
	 * @brief 
	 * 发送广播消息
	 */
	//if(flag)
	{
		//INFO("Now broadcast message");
		//fprintf(stderr, "json: %s\n", blobmsg_format_json(ubusMsg.head, true));
		int err = ubus_notify(gctx,  &stVirtualObj, "data", ubusMsg.head, -1); /*do not expect a response*/
		if (err)
			WARNING( "Notify failed: %s\n", ubus_strerror(err));
	}
	#else
	IPC_DATA_TYPE *pstNotify = malloc_ipc_data(_INSIGHT_VIRTUAL);
	if(NULL == pstNotify)
	{
		WARNING("Cannot get memory");
	}

	for(i = 0;i < TERMINAL_HASH_SIZE;i++)
	{
		if(list_empty(&stTerminal[i]) )
		{
			continue;
		}
		list_for_each_entry_safe(pstOptionTmp,pstOptionPos,&stTerminal[i],listTerm)
		{
			//do_update_datebase(pstOptionTmp,&ubusMsg);
			if(pstNotify != NULL)
				do_create_virtual_notify(pstOptionTmp,pstNotify);
				
			slDataAccount++;
			list_del(&pstOptionTmp->listTerm);
			//free(pstOptionTmp);
			free_terminal(pstOptionTmp);
		}
	}

	if(pstNotify != NULL)
	{
		free(pstNotify);
		pstNotify = NULL;
	}
	
	#endif
}
#ifndef TRAFFIC_CMCC
void do_create_urlmsg(HTTP_URL_INFO *pstOptionTmp,struct blob_buf *buf)
{
	void *tbl;		
	char strBuf[1024] = {0};
	snprintf(strBuf,1024,"%02x:%02x:%02x:%02x:%02x:%02x",
	pstOptionTmp->ucMacAddr[0],pstOptionTmp->ucMacAddr[1],pstOptionTmp->ucMacAddr[2],
	pstOptionTmp->ucMacAddr[3],pstOptionTmp->ucMacAddr[4],pstOptionTmp->ucMacAddr[5]);

	uint32_t ulIp = pstOptionTmp->addr.saddr;
	tbl = blobmsg_open_table(buf, NULL);
	blobmsg_add_string(buf, term_info_policy[_TREMINAL_INFO_MAC].name, strBuf);
	blobmsg_add_string(buf,  term_info_policy[_TREMINAL_INFO_IP].name, int_ntoa(ulIp));

	bzero(strBuf,1024);
	snprintf(strBuf,1024,"http://%s%s",pstOptionTmp->strHost,pstOptionTmp->strUrl);
	blobmsg_add_string(buf,term_info_policy[_TREMINAL_INFO_VALUE].name, strBuf);

 	bzero(strBuf,1024);	
	strftime(strBuf,128,"%Y-%m-%d %H:%M:%S",localtime((time_t *)&pstOptionTmp->ulTime));
	blobmsg_add_string(buf,term_info_policy[_TREMINAL_INFO_ONLINE].name, strBuf);

	blobmsg_close_table(buf, tbl);

	//return RET_SUCCESS;

}
#endif



void record_http_cb(struct ev_loop *loop, ev_timer *watcher, int revents)
{	
	#ifndef TRAFFIC_CMCC
	int slDataAccount = 0;
	struct list_head *pstHttpList = watcher->data;
	HTTP_URL_INFO *pstOptionTmp = NULL;
    HTTP_URL_INFO *pstOptionPos = NULL;
	#if 0
	void *array;
	blob_buf_init(&ubusMsg, 0);
	array = blobmsg_open_array(&ubusMsg, term_broad_policy[_TREMINAL_URL].name);

	list_for_each_entry_safe(pstOptionTmp,pstOptionPos,pstHttpList,list)
	{
		/**
		 * @brief 
		 * 通过回复报文确定了
		 */
		//if(pstOptionTmp->bitMatch)
		{
			printf("mac-->%02x:%02x:%02x:%02x:%02x:%02x: url:%s%s need record \n",
					pstOptionTmp->ucMacAddr[0],pstOptionTmp->ucMacAddr[1],pstOptionTmp->ucMacAddr[2],
					pstOptionTmp->ucMacAddr[3],pstOptionTmp->ucMacAddr[4],pstOptionTmp->ucMacAddr[5],
					pstOptionTmp->strHost,pstOptionTmp->strUrl);
		}
		slDataAccount++;
		do_update_url(pstOptionTmp);
		do_create_urlmsg(pstOptionTmp,&ubusMsg);

		list_del(&pstOptionTmp->list);
        free(pstOptionTmp);
		pstOptionTmp = NULL;
	}
	blobmsg_close_array(&ubusMsg, array);
	blobmsg_add_u32(&ubusMsg, term_broad_policy[_TREMINAL_COUNT].name, slDataAccount);

	int err = ubus_notify(gctx,  &stVirtualObj, term_broad_policy[_TREMINAL_URL].name, ubusMsg.head, -1); /*do not expect a response*/
	if (err)
		WARNING( "Notify failed: %s\n", ubus_strerror(err));
	#else
	int index = 0;
	int slMaxdataNum =  DEFAULT_INSIGHT_SIZE / sizeof(HTTP_URL_INFO);
	IPC_DATA_TYPE *pstNotify = (IPC_DATA_TYPE *)malloc_ipc_data(_INSIGHT_HTTPLOG);
	HTTP_URL_INFO *pstNotifyUrl = pstNotify->ucData;
	
	if(NULL == pstNotify)
	{
		WARNING("Cannot get memory for http log");
	}
	
	list_for_each_entry_safe(pstOptionTmp,pstOptionPos,pstHttpList,list)
	{
		/**
		 * @brief 
		 * 通过回复报文确定了
		 */
		//if(pstOptionTmp->bitMatch)
		{
			INFO("mac-->%02x:%02x:%02x:%02x:%02x:%02x: url:%s%s need record \n",
					pstOptionTmp->ucMacAddr[0],pstOptionTmp->ucMacAddr[1],pstOptionTmp->ucMacAddr[2],
					pstOptionTmp->ucMacAddr[3],pstOptionTmp->ucMacAddr[4],pstOptionTmp->ucMacAddr[5],
					pstOptionTmp->strHost,pstOptionTmp->strUrl);
		}
		slDataAccount++;
		//do_update_url(pstOptionTmp);
		if(pstNotify != NULL)
		{
			memcpy(pstNotifyUrl + index,pstOptionTmp,sizeof(HTTP_URL_INFO));
			index++;
			if(index == slMaxdataNum)
			{
				pstNotify->slDataLen = index * sizeof(HTTP_URL_INFO);
				notify_insight_data(pstNotify);

				index = 0;
				pstNotify->slDataLen = 0;
				memset(pstNotify->ucData,0,DEFAULT_INSIGHT_SIZE);
			}
		}
		//do_create_http_notify(pstOptionTmp,pstNotify);

		list_del(&pstOptionTmp->list);
        free(pstOptionTmp);
		pstOptionTmp = NULL;
	}

	if(pstNotify != NULL)
	{
		if(index != 0)
		{
			pstNotify->slDataLen = index * sizeof(HTTP_URL_INFO);
			notify_insight_data(pstNotify);
		}
		
		free(pstNotify);
		pstNotify = NULL;
	}
	
	#endif
	#endif
}
static TERM_RECORD_INFO *find_term_byhash(unsigned char *mac)
{
    /*hash method need change*/
    int i = 0;
    unsigned int value = 0;
    for(i = 0;i < 6;i++)
    {
        value += mac[i];
    }
    value = value % TERMINAL_HASH_SIZE;
    //printf("func:%s-->%02x:%02x:%02x:%02x:%02x:%02x \n",__FUNCTION__,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    TERM_RECORD_INFO *pstFindTerm = NULL;
    list_for_each_entry(pstFindTerm,&stTerminal[value],listTerm)
    {
        if(memcmp(pstFindTerm->ucMacAddr,mac,6) == 0)
        {
            pstFindTerm->stTimeStamp = time(NULL);
            return pstFindTerm;
        }
    }
    //printf("-->>>>>>>>>>>>>add new terminal \n");
    /*not find */
    pstFindTerm = calloc(1,sizeof(TERM_RECORD_INFO));
	if(NULL == pstFindTerm)
	{
		ERROR("RECORD-->calloc failed ");
		return NULL;
	}
    memset(pstFindTerm,0,sizeof(TERM_RECORD_INFO));
    memcpy(pstFindTerm->ucMacAddr,mac,6);
    pstFindTerm->stTimeStamp = time(NULL);
    // for(i = 0;i < _TARGET_MAX;i++)
    // {
    //     init_list_head(&pstFindTerm->listData[i]);
    // }
    list_insert_tail(&pstFindTerm->listTerm,&stTerminal[value]);
	INFO("RECORD-->add new treminal %02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return pstFindTerm;
}

static inline DATA_RECORD_INFO *malloc_new_record(void *data,int len,ENUM_TARGET_TYPE eTarget,const char *const strName)
{
	DATA_RECORD_INFO *pstTmp = calloc(1,sizeof(DATA_RECORD_INFO) + len + 10);
	if(pstTmp == NULL)
	{
		ERROR("RECORD-->calloc failed ");
		return NULL;
	}
	memset(pstTmp,0,sizeof(DATA_RECORD_INFO) + len + 10);

	pstTmp->nextaccout  = NULL;
	pstTmp->stTimeStamp = time(NULL);
	pstTmp->eRecordType = eTarget;
	pstTmp->slRecordLen = len;
	strncpy(pstTmp->strTypeName,strName,sizeof(pstTmp->strTypeName));
	memcpy(pstTmp->ucData,data,len);

	return pstTmp;
}

int do_record_data(void *data,int len,void *pri)
{
    m_priv_t *priv	= pri;
	const RULE_DETAIL_INFO *const pstRuleInfo     = priv->pstRuleDetail;
	const TARGET_TYPE_MAP  *const pstTargetMap 	  = pstRuleInfo->stTargetInfo.pstTargetMap;

	ENUM_TARGET_TYPE eTarget = pstTargetMap->eType;
	if(eTarget >= _TARGET_MAX)
	{
		printf("here get a wrong target-->%d %s \n",eTarget,pstTargetMap->strName);
		return RET_FAILED;
	}
	//printf("priv->slDir = %d \n",priv->slDir);
    /*reply  use dst*/
    TERM_RECORD_INFO *pstFindTerm = find_term_byhash(priv->slDir ? priv->stEthInfo.h_dest : priv->stEthInfo.h_source );
    if(NULL == pstFindTerm)
    {
        return RET_FAILED;
    }
    pstFindTerm->ulIPAddr = priv->slDir ? htonl(priv->ht.daddr) : htonl(priv->ht.saddr);

	/**
	 * @brief 
	 * 	没有记录过此类型的数据
	 */
	if(pstFindTerm->pstDataRecord[eTarget] == NULL)
	{
		DATA_RECORD_INFO *pstTmp = malloc_new_record(data,len,eTarget,pstTargetMap->strName);
		if(NULL == pstTmp)
		{
			return RET_FAILED;
		}
		pstFindTerm->pstDataRecord[eTarget] = pstTmp;
		pstFindTerm->usDataCount++;
	}
	else
	{
		/**
		 * @brief 
		 * 	已经记录过得数据
		 *  匹配是否相等，避免多账号
		 */
		DATA_RECORD_INFO *pstTmp 	 = pstFindTerm->pstDataRecord[eTarget];
		do
		{
			if(len == pstTmp->slRecordLen && (0 == strncasecmp(data,(void *)pstTmp->ucData,len)))
			{
				/*相当账号的多次记录,只是更新时间戳*/
				pstTmp->stTimeStamp = time(NULL);
				return RET_SUCCESS;
			}
			pstTmp = pstTmp->nextaccout;
		}while(pstTmp);

		pstTmp 	 = pstFindTerm->pstDataRecord[eTarget];
		DATA_RECORD_INFO *pstNew = malloc_new_record(data,len,eTarget,pstTargetMap->strName);
		if(pstNew == NULL)
		{
			return RET_FAILED;
		}
		pstNew->nextaccout = pstTmp;
		pstFindTerm->pstDataRecord[eTarget] = pstNew;
		pstFindTerm->usDataCount++;
		INFO("RECORD-->terminal  %02x:%02x:%02x:%02x:%02x:%02x need add a new virtual account type:%d account:%s",
			pstFindTerm->ucMacAddr[0],pstFindTerm->ucMacAddr[1],pstFindTerm->ucMacAddr[2],
			pstFindTerm->ucMacAddr[3],pstFindTerm->ucMacAddr[4],pstFindTerm->ucMacAddr[5],eTarget,data);
			
		return RET_SUCCESS;
	}
    return RET_FAILED;
}

extern int syslog_en;
#ifndef TRAFFIC_CMCC
static int ubus_log(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	
	
	int ret = 0;
	struct blob_attr *item;
	struct blob_attr *tb[__LOG_MAX] = {NULL};

	ret = blobmsg_parse(log_policy, ARRAY_SIZE(log_policy), tb, blob_data(msg), blob_len(msg));
	if (tb[LOG_ENABLE] == NULL || ret) {
		printf("Get log message but no date here,ubus err-->%s  \n",ubus_strerror(ret));
		return -1;
	}
	item = tb[LOG_ENABLE];
	bool logEn = blobmsg_get_bool(item);
	syslog_en = logEn == true ? 2: 0;
	change_log_status(logEn);
	blob_buf_init(&ubusMsg, 0);
	blobmsg_add_u8(&ubusMsg, log_policy[LOG_ENABLE].name, logEn);
	ubus_send_reply(ctx, req, ubusMsg.head);

	char strBuf[64] = {0};
	snprintf(strBuf,64,"echo \" log:%s  \" > /tmp/virtuallog",logEn ? "enable":"dsiable");
	system(strBuf);
    return RET_SUCCESS;
}

static int virtual_get_req(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{	
	int ret = 0;
	int flag = 0;
	int i = 0;
	const char *space = " ";
	char strTmpBuf[512] = {0};
	char strSqlFind[2048] = {"select * from record where "};
	int slEntryNum = 0;
	void * array = NULL,*tbl = NULL;
	DATABASE_RECORD_ENTRY    *pstDbEntry     = NULL;

	INFO("someone is requesting datebase with method %s and json:%s \n", method,blobmsg_format_json(msg, true));

	struct blob_attr *item;
	struct blob_attr *tb[_REQ_TERM_MAX] = {NULL};

	ret = blobmsg_parse(req_policy, ARRAY_SIZE(req_policy), tb, blob_data(msg), blob_len(msg));
	if (tb[_REQ_INFO] == NULL || ret) {
		printf("Get req message but no date here,ubus err-->%s  \n",ubus_strerror(ret));
		return -1;
	}

	item = tb[_REQ_INFO];
	
	ret = blobmsg_parse(req_info_policy, ARRAY_SIZE(req_info_policy), tb, blobmsg_data(item), blobmsg_data_len(item));
	if (ret)
		fprintf(stderr, "parse message %s\n", ubus_strerror(ret));

	if(tb[_REQ_TERM_MAC])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," mac='%s' ",blobmsg_get_string(tb[_REQ_TERM_MAC]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	if(tb[_REQ_TERM_IP])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," %s ip='%s' ",flag == 1 ? "and" : space,blobmsg_get_string(tb[_REQ_TERM_IP]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	if(tb[_REQ_TERM_TYPE])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," %s type='%s' ",flag == 1 ? "and" : space,blobmsg_get_string(tb[_REQ_TERM_TYPE]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	if(tb[_REQ_TERM_VAL])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," %s value = '%s'",flag == 1 ? "and" : space,blobmsg_get_string(tb[_REQ_TERM_VAL]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	if(tb[_REQ_TERM_ONLINE_START_DATE])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		if(!tb[_REQ_TERM_ONLINE_END_DATE])  /*筛选当天或当天的指定数据*/
		{
			if(tb[_REQ_TERM_ONLINE_START_TIME]) /*删选指定时间数据*/
			{
				snprintf(strTmpBuf,sizeof(strTmpBuf)," %s datetime(online)=datetime('%s %s') ",
				flag == 1 ? "and" : space,
				blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]),blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_TIME]));
			}
			else /*筛选当天全部数据*/
			{
				snprintf(strTmpBuf,sizeof(strTmpBuf)," %s (datetime(online) between datetime('%s 00:00:00') and datetime('%s 23:59:59') ) ",
				flag == 1 ? "and" : space,
				blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]),blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]));
			}
		}
		else
		{
			snprintf(strTmpBuf,sizeof(strTmpBuf)," %s (datetime(online) between datetime('%s %s') and datetime('%s %s') )",
			flag == 1 ? "and" : space,
			blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]),
			tb[_REQ_TERM_ONLINE_START_TIME] ? blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_TIME]) : "00:00:00",
			blobmsg_get_string(tb[_REQ_TERM_ONLINE_END_DATE]),
			tb[_REQ_TERM_ONLINE_END_TIME] ? blobmsg_get_string(tb[_REQ_TERM_ONLINE_END_TIME]) : "23:59:59");
		}
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}

	if(tb[_REQ_TERM_ACTIVE_START_DATE])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		if(!tb[_REQ_TERM_ACTIVE_END_DATE])
		{
			if(tb[_REQ_TERM_ACTIVE_START_TIME]) /*删选指定时间数据*/
			{
				snprintf(strTmpBuf,sizeof(strTmpBuf)," %s datetime(active)=datetime('%s %s') ",
				flag == 1 ? "and" : space,
				blobmsg_get_string(tb[_REQ_TERM_ACTIVE_START_DATE]),blobmsg_get_string(tb[_REQ_TERM_ACTIVE_START_TIME]));
			}
			else /*筛选当天全部数据*/
			{
				snprintf(strTmpBuf,sizeof(strTmpBuf)," %s (datetime(active) between datetime('%s 00:00:00') and datetime('%s 23:59:59') ) ",
				flag == 1 ? "and" : space,
				blobmsg_get_string(tb[_REQ_TERM_ACTIVE_START_DATE]),blobmsg_get_string(tb[_REQ_TERM_ACTIVE_START_DATE]));
			}
		}
		else
		{
			snprintf(strTmpBuf,sizeof(strTmpBuf)," %s (datetime(active) between datetime('%s %s') and datetime('%s %s') ) ",
			flag == 1 ? "and" : space,
			blobmsg_get_string(tb[_REQ_TERM_ACTIVE_START_DATE]),
			tb[_REQ_TERM_ACTIVE_START_TIME] ? blobmsg_get_string(tb[_REQ_TERM_ACTIVE_START_TIME]) : "00:00:00",
			blobmsg_get_string(tb[_REQ_TERM_ACTIVE_END_DATE]),
			tb[_REQ_TERM_ACTIVE_END_TIME] ? blobmsg_get_string(tb[_REQ_TERM_ACTIVE_END_TIME]) : "23:59:59");
		}
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	strcat(strSqlFind," ; ");
	if(flag != 0)
	{
		INFO("someone is requesting database with cmd %s",strSqlFind);
	}
	else
	{
		WARNING("someone is requesting database with wrong cmd %s",strSqlFind);
	}
	
	blob_buf_init(&ubusMsg, 0);
	array = blobmsg_open_array(&ubusMsg, term_broad_policy[_TREMINAL_BROAD].name);
	
	if(do_find_terminal(strSqlFind,&slEntryNum,&pstDbEntry) == RET_SUCCESS && slEntryNum > 0)
	{
		for(i = 0;i < slEntryNum;i++)
		{
			tbl = blobmsg_open_table(&ubusMsg, NULL);
			blobmsg_add_string(&ubusMsg, term_info_policy[_TREMINAL_INFO_MAC].name, pstDbEntry[i].strMac);
			blobmsg_add_string(&ubusMsg,  term_info_policy[_TREMINAL_INFO_IP].name, pstDbEntry[i].strIp);
			blobmsg_add_string(&ubusMsg,term_info_policy[_TREMINAL_INFO_ONLINE].name, pstDbEntry[i].strOnlineTime);
			blobmsg_add_string(&ubusMsg,term_info_policy[_TREMINAL_INFO_ACTIVE].name,  pstDbEntry[i].strActiveTime);
			blobmsg_add_u32(&ubusMsg,term_info_policy[_TREMINAL_INFO_NUM].name,  pstDbEntry[i].slAcountNum);
			blobmsg_add_string(&ubusMsg,term_info_policy[_TREMINAL_INFO_TYPE].name, pstDbEntry[i].strAccountType); 
			blobmsg_add_string(&ubusMsg,term_info_policy[_TREMINAL_INFO_VALUE].name,  pstDbEntry[i].strAccountVal);
			blobmsg_close_table(&ubusMsg, tbl);
		}
	}
	blobmsg_close_array(&ubusMsg, array);
	blobmsg_add_u32(&ubusMsg, term_broad_policy[_TREMINAL_COUNT].name, slEntryNum);

	ubus_send_reply(ctx, req, ubusMsg.head);

	if(pstDbEntry)
    {
        free(pstDbEntry);
        pstDbEntry = NULL;
    }    
	return RET_SUCCESS;
}
static int virtual_get_email(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{

	int ret = 0;
	int flag = 0;
	int i = 0;
	const char *space = " ";
	char strTmpBuf[1024] = {0};
	char strSqlFind[2048] = {"select * from email where "};
	int slEntryNum = 0;
	void * array = NULL,*tbl = NULL;
	EMAIL_DB_ENTRY    *pstDbEntry     = NULL;


	INFO("someone is requesting datebase with method %s and json:%s \n", method,blobmsg_format_json(msg, true));
	struct blob_attr *item;
	struct blob_attr *tb[_EMAIL_INFO_MAX] = {NULL};

	ret = blobmsg_parse(email_policy, ARRAY_SIZE(email_policy), tb, blob_data(msg), blob_len(msg));
	if (tb[_EMAIL_INFO] == NULL || ret) {
		printf("Get req message but no date here,ubus err-->%s  \n",ubus_strerror(ret));
		return -1;
	}

	item = tb[_EMAIL_INFO];
	ret = blobmsg_parse(req_info_policy, ARRAY_SIZE(req_info_policy), tb, blobmsg_data(item), blobmsg_data_len(item));
	if (ret)
		fprintf(stderr, "parse message %s\n", ubus_strerror(ret));
		
	if(tb[_REQ_TERM_MAC])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," mac='%s' ",blobmsg_get_string(tb[_REQ_TERM_MAC]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	if(tb[_REQ_TERM_IP])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," %s ip='%s' ",flag == 1 ? "and" : space,blobmsg_get_string(tb[_REQ_TERM_IP]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	if(tb[_REQ_TERM_START_INDEX])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," %s id > %d  ",flag == 1 ? "and" : space,blobmsg_get_u32(tb[_REQ_TERM_START_INDEX]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}

	if(tb[_REQ_TERM_ONLINE_START_DATE])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		if(!tb[_REQ_TERM_ONLINE_END_DATE])  /*筛选当天或当天的指定数据*/
		{
			if(tb[_REQ_TERM_ONLINE_START_TIME]) /*删选指定时间数据*/
			{
				snprintf(strTmpBuf,sizeof(strTmpBuf)," %s datetime(online)=datetime('%s %s') ",
				flag == 1 ? "and" : space,
				blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]),blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_TIME]));
			}
			else /*筛选当天全部数据*/
			{
				snprintf(strTmpBuf,sizeof(strTmpBuf)," %s (datetime(online) between datetime('%s 00:00:00') and datetime('%s 23:59:59') ) ",
				flag == 1 ? "and" : space,
				blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]),blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]));
			}
		}
		else
		{
			snprintf(strTmpBuf,sizeof(strTmpBuf)," %s (datetime(online) between datetime('%s %s') and datetime('%s %s') )",
			flag == 1 ? "and" : space,
			blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]),
			tb[_REQ_TERM_ONLINE_START_TIME] ? blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_TIME]) : "00:00:00",
			blobmsg_get_string(tb[_REQ_TERM_ONLINE_END_DATE]),
			tb[_REQ_TERM_ONLINE_END_TIME] ? blobmsg_get_string(tb[_REQ_TERM_ONLINE_END_TIME]) : "23:59:59");
		}
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	strcat(strSqlFind," ; ");

	if(flag != 0)
	{
		INFO("someone is requesting database with cmd %s",strSqlFind);
	}
	else
	{
		bzero(strSqlFind,ARRAY_SIZE(strSqlFind));
		strcpy(strSqlFind,"select * from email ;");
		WARNING("someone is requesting database without any  select contidion  %s",strSqlFind);
	}

	blob_buf_init(&ubusMsg, 0);
	array = blobmsg_open_array(&ubusMsg, term_broad_policy[_TREMINAL_EMAIL].name);
	
	if(do_find_email(strSqlFind,&slEntryNum,&pstDbEntry) == RET_SUCCESS && slEntryNum > 0)
	{
		for(i = 0;i < slEntryNum;i++)
		{
			tbl = blobmsg_open_table(&ubusMsg, NULL);
			blobmsg_add_string(&ubusMsg, term_email_policy[_EMAIL_INFO_MAC].name, pstDbEntry[i].strMac);
			blobmsg_add_string(&ubusMsg,  term_email_policy[_EMAIL_INFO_IP].name, pstDbEntry[i].strIp);
			blobmsg_add_string(&ubusMsg,term_email_policy[_EMAIL_INFO_ONLINE].name, pstDbEntry[i].strOnlineTime);
			blobmsg_add_string(&ubusMsg,term_email_policy[_EMAIL_INFO_ACCOUNT].name,  pstDbEntry[i].strUser);
			blobmsg_add_string(&ubusMsg,term_email_policy[_EMAIL_INFO_KEY].name,  pstDbEntry[i].strKey);
			blobmsg_add_string(&ubusMsg,term_email_policy[_EMAIL_INFO_DIRECTION].name,  pstDbEntry[i].strDir);
			blobmsg_add_string(&ubusMsg,term_email_policy[_EMAIL_INFO_FROM].name,  pstDbEntry[i].strFrom);
			blobmsg_add_string(&ubusMsg,term_email_policy[_EMAIL_INFO_TO].name,  pstDbEntry[i].strTo);
			blobmsg_add_string(&ubusMsg,term_email_policy[_EMAIL_INFO_SUBJECT].name,  pstDbEntry[i].ucSubject);
			blobmsg_add_string(&ubusMsg,term_email_policy[_EMAIL_INFO_CONTENT].name,  pstDbEntry[i].strContent);
			blobmsg_add_string(&ubusMsg,term_email_policy[_EMAIL_INFO_ATTACH].name,  pstDbEntry[i].strAttach);
			blobmsg_close_table(&ubusMsg, tbl);
		}
	}
	blobmsg_close_array(&ubusMsg, array);
	blobmsg_add_u32(&ubusMsg, term_broad_policy[_TREMINAL_COUNT].name, slEntryNum);

	ubus_send_reply(ctx, req, ubusMsg.head);

	if(pstDbEntry)
    {
        free(pstDbEntry);
        pstDbEntry = NULL;
    }    

	return RET_SUCCESS;
}

static int virtual_get_url(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	int ret = 0;
	int flag = 0;
	int i = 0;
	const char *space = " ";
	char strTmpBuf[1024] = {0};
	char strSqlFind[2048] = {"select * from httplog where "};
	int slEntryNum = 0;
	void * array = NULL,*tbl = NULL;
	HTTP_DB_ENTRY    *pstDbEntry     = NULL;


	INFO("someone is requesting datebase with method %s and json:%s \n", method,blobmsg_format_json(msg, true));
	struct blob_attr *item;
	struct blob_attr *tb[_REQ_TERM_MAX] = {NULL};

	ret = blobmsg_parse(url_policy, ARRAY_SIZE(url_policy), tb, blob_data(msg), blob_len(msg));
	if (tb[_URL_INFO] == NULL || ret) {
		printf("Get req message but no date here,ubus err-->%s  \n",ubus_strerror(ret));
		return -1;
	}

	item = tb[_URL_INFO];
	ret = blobmsg_parse(req_info_policy, ARRAY_SIZE(req_info_policy), tb, blobmsg_data(item), blobmsg_data_len(item));
	if (ret)
		fprintf(stderr, "parse message %s\n", ubus_strerror(ret));
		
	if(tb[_REQ_TERM_MAC])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," mac='%s' ",blobmsg_get_string(tb[_REQ_TERM_MAC]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	if(tb[_REQ_TERM_IP])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," %s ip='%s' ",flag == 1 ? "and" : space,blobmsg_get_string(tb[_REQ_TERM_IP]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	if(tb[_REQ_TERM_VAL])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," %s value = '%s'",flag == 1 ? "and" : space,blobmsg_get_string(tb[_REQ_TERM_VAL]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	if(tb[_REQ_TERM_START_INDEX])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		snprintf(strTmpBuf,sizeof(strTmpBuf)," %s id > %d  ",flag == 1 ? "and" : space,blobmsg_get_u32(tb[_REQ_TERM_START_INDEX]));
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}

	if(tb[_REQ_TERM_ONLINE_START_DATE])
	{
		bzero(strTmpBuf,sizeof(strTmpBuf));
		if(!tb[_REQ_TERM_ONLINE_END_DATE])  /*筛选当天或当天的指定数据*/
		{
			if(tb[_REQ_TERM_ONLINE_START_TIME]) /*删选指定时间数据*/
			{
				snprintf(strTmpBuf,sizeof(strTmpBuf)," %s datetime(online)=datetime('%s %s') ",
				flag == 1 ? "and" : space,
				blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]),blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_TIME]));
			}
			else /*筛选当天全部数据*/
			{
				snprintf(strTmpBuf,sizeof(strTmpBuf)," %s (datetime(online) between datetime('%s 00:00:00') and datetime('%s 23:59:59') ) ",
				flag == 1 ? "and" : space,
				blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]),blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]));
			}
		}
		else
		{
			snprintf(strTmpBuf,sizeof(strTmpBuf)," %s (datetime(online) between datetime('%s %s') and datetime('%s %s') )",
			flag == 1 ? "and" : space,
			blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_DATE]),
			tb[_REQ_TERM_ONLINE_START_TIME] ? blobmsg_get_string(tb[_REQ_TERM_ONLINE_START_TIME]) : "00:00:00",
			blobmsg_get_string(tb[_REQ_TERM_ONLINE_END_DATE]),
			tb[_REQ_TERM_ONLINE_END_TIME] ? blobmsg_get_string(tb[_REQ_TERM_ONLINE_END_TIME]) : "23:59:59");
		}
		strcat(strSqlFind,strTmpBuf);
		flag = 1;
	}
	strcat(strSqlFind," ; ");
	if(flag != 0)
	{
		INFO("someone is requesting database with cmd %s",strSqlFind);
	}
	else
	{
		bzero(strSqlFind,ARRAY_SIZE(strSqlFind));
		strcpy(strSqlFind,"select * from httplog ;");
		WARNING("someone is requesting database without any  select contidion  %s",strSqlFind);
	}

	blob_buf_init(&ubusMsg, 0);
	array = blobmsg_open_array(&ubusMsg, term_broad_policy[_TREMINAL_URL].name);
	
	if(do_find_url(strSqlFind,&slEntryNum,&pstDbEntry) == RET_SUCCESS && slEntryNum > 0)
	{
		for(i = 0;i < slEntryNum;i++)
		{
			tbl = blobmsg_open_table(&ubusMsg, NULL);
			blobmsg_add_string(&ubusMsg, term_info_policy[_TREMINAL_INFO_MAC].name, pstDbEntry[i].strMac);
			blobmsg_add_string(&ubusMsg,  term_info_policy[_TREMINAL_INFO_IP].name, pstDbEntry[i].strIp);
			blobmsg_add_string(&ubusMsg,term_info_policy[_TREMINAL_INFO_ONLINE].name, pstDbEntry[i].strOnlineTime);
			blobmsg_add_string(&ubusMsg,term_info_policy[_TREMINAL_INFO_VALUE].name,  pstDbEntry[i].strUrl);
			blobmsg_close_table(&ubusMsg, tbl);
		}
	}

	blobmsg_close_array(&ubusMsg, array);
	blobmsg_add_u32(&ubusMsg, term_broad_policy[_TREMINAL_COUNT].name, slEntryNum);

	ubus_send_reply(ctx, req, ubusMsg.head);

	if(pstDbEntry)
    {
        free(pstDbEntry);
        pstDbEntry = NULL;
    }    

	return RET_SUCCESS;
}
#endif

void record_virtual_data(void *data,int slDataLen)
{
	int i = 0;
	TERM_RECORD_INFO        stTermInfo;
	DATABASE_RECORD_ENTRY stUpdateEntry;
	IPC_DATA_TYPE *pstInsight 	 = (IPC_DATA_TYPE *)data;
	VIRTUAL_IPC_DATA *pstIpcData = (VIRTUAL_IPC_DATA *)pstInsight->ucData;
	int slValidDataLen           =  pstInsight->slDataLen < slDataLen ?  pstInsight->slDataLen : slDataLen;
	int slNum                    = slValidDataLen / sizeof(VIRTUAL_IPC_DATA);
	INFO("Now need handle virtual info slDataLen %d %d %d slNum %d \n",slDataLen,pstInsight->slDataLen,sizeof(VIRTUAL_IPC_DATA),slNum);

	#ifndef TRAFFIC_CMCC
	void *array;
	blob_buf_init(&ubusMsg, 0);
	array = blobmsg_open_array(&ubusMsg, term_broad_policy[_TREMINAL_BROAD].name);
	#endif
	uint32_t ip = 0;
	char strBuf[128] = {0};
	char timestamp[128] = {0};
	
	printf("id \t mac \t\t\t ip\t\t     num    type    online\t\t\tactive\t\t\t value\n");
	for(i = 0;i < slNum;i++,pstIpcData++)
	{
		bzero(&stUpdateEntry,sizeof(stUpdateEntry));
		stTermInfo.stTimeStamp = time(NULL);
		stTermInfo.ulIPAddr = pstIpcData->ulIp;
		memcpy(stTermInfo.ucMacAddr,pstIpcData->ucMac,6);

		bzero(strBuf,sizeof(strBuf));
		bzero(timestamp,sizeof(timestamp));
		
		snprintf(strBuf,sizeof(strBuf),"%02x:%02x:%02x:%02x:%02x:%02x",
		stTermInfo.ucMacAddr[0],stTermInfo.ucMacAddr[1],stTermInfo.ucMacAddr[2],
		stTermInfo.ucMacAddr[3],stTermInfo.ucMacAddr[4],stTermInfo.ucMacAddr[5]);
		ip = htonl(stTermInfo.ulIPAddr);
		strftime(timestamp,128,"%Y-%m-%d %H:%M:%S",localtime(&stTermInfo.stTimeStamp));

		printf("%d \t %s  \t %-20s %d     %-8s%-20s \t%-20s \t%-20s \n",i + 1,
		strBuf, 
		int_ntoa(ip),pstIpcData->stAccountInfo.num,pstIpcData->stAccountInfo.strType,
		timestamp,timestamp,pstIpcData->stAccountInfo.value);
		
		#ifndef TRAFFIC_CMCC
		do_update_terminal(&stTermInfo,&pstIpcData->stAccountInfo,&stUpdateEntry);
		do_create_ubusmsg(stTermInfo.ucMacAddr,stTermInfo.ulIPAddr,
			stUpdateEntry.strOnlineTime,stUpdateEntry.strActiveTime,&pstIpcData->stAccountInfo,&ubusMsg);
		#endif
	}
	#ifndef TRAFFIC_CMCC
	blobmsg_close_array(&ubusMsg, array);
	blobmsg_add_u32(&ubusMsg, term_broad_policy[_TREMINAL_COUNT].name, slNum);

	int err = ubus_notify(gctx,  &stVirtualObj, term_broad_policy[_TREMINAL_URL].name, ubusMsg.head, -1); /*do not expect a response*/
	if (err)
		WARNING( "Notify failed: %s\n", ubus_strerror(err));
	#endif

}
void record_http_data(void *data,int slDataLen)
{
	#ifndef TRAFFIC_CMCC
	int i = 0;
	IPC_DATA_TYPE *pstInsight 	 = (IPC_DATA_TYPE *)data;
	HTTP_URL_INFO *pstNotifyUrl  = (HTTP_URL_INFO *)pstInsight->ucData;
	int slValidDataLen           =  pstInsight->slDataLen < slDataLen ?  pstInsight->slDataLen : slDataLen;
	int slNum                    = slValidDataLen / sizeof(HTTP_URL_INFO);

	void *array;
	blob_buf_init(&ubusMsg, 0);
	array = blobmsg_open_array(&ubusMsg, term_broad_policy[_TREMINAL_URL].name);

	for(i = 0;i < slNum;i++,pstNotifyUrl++)
	{
		do_update_url(pstNotifyUrl);
		do_create_urlmsg(pstNotifyUrl,&ubusMsg);

	}
	blobmsg_close_array(&ubusMsg, array);
	blobmsg_add_u32(&ubusMsg, term_broad_policy[_TREMINAL_COUNT].name, slNum);

	int err = ubus_notify(gctx,  &stVirtualObj, term_broad_policy[_TREMINAL_URL].name, ubusMsg.head, -1); /*do not expect a response*/
	if (err)
		WARNING( "Notify failed: %s\n", ubus_strerror(err));
	#endif
}
/**
 * @brief 
 * 	在这解析邮件
 * 	但是这样做有可能阻塞套接字导致耽搁太久而丢包
 * @param data 
 * @param slDataLen 
 */
void record_email_data(void *data,int slDataLen)
{
 	#ifndef TRAFFIC_CMCC
	IPC_DATA_TYPE *pstInsight 	  = (IPC_DATA_TYPE *)data;
	EMAIL_INSIGHT_IPC *pstNotify  = (EMAIL_INSIGHT_IPC *)pstInsight->ucData;
	SMTP_PARSE_INFO stEmailInfo;
    bzero(&stEmailInfo,sizeof(stEmailInfo));

	void *tbl = NULL, * array = NULL;
	char strBuf[512] = {0};
	time_t nowtime = time(NULL);

	if(parse_email(pstNotify->strFileName,pstNotify->emailType,&stEmailInfo) < 0)
	{
		WARNING( "need parse email %s failed",pstNotify->strFileName);
		unlink(pstNotify->strFileName);
		return;
	}
	if(pstNotify->emailType == _EMAIL_SMTP)
	{
		memcpy(stEmailInfo.strTo,pstNotify->strTo,ARRAY_SIZE(pstNotify->strTo));
	}
	do_update_email(&stEmailInfo,pstNotify);

	unlink(pstNotify->strFileName);
	struct blob_buf *buf = &ubusMsg;

	blob_buf_init(&ubusMsg, 0);
	array = blobmsg_open_array(buf, term_broad_policy[_TREMINAL_EMAIL].name);

	tbl = blobmsg_open_table(buf, NULL);

	snprintf(strBuf,512,"%02x:%02x:%02x:%02x:%02x:%02x",
	pstNotify->ucMac[0],pstNotify->ucMac[1],pstNotify->ucMac[2],
	pstNotify->ucMac[3],pstNotify->ucMac[4],pstNotify->ucMac[5]);

	blobmsg_add_string(buf,  term_email_policy[_EMAIL_INFO_MAC].name, strBuf);
	blobmsg_add_string(buf,  term_email_policy[_EMAIL_INFO_IP].name, int_ntoa (pstNotify->ulIp));
	bzero(strBuf,512);
	strftime(strBuf,128,"%Y-%m-%d %H:%M:%S",localtime(&nowtime));
	blobmsg_add_string(buf,term_email_policy[_EMAIL_INFO_ONLINE].name, strBuf);

	if(strlen(pstNotify->strUser))
	{
		blobmsg_add_string(buf,term_email_policy[_EMAIL_INFO_ACCOUNT].name, pstNotify->strUser);
	}
	if(strlen(pstNotify->strKey))
	{
		blobmsg_add_string(buf,term_email_policy[_EMAIL_INFO_KEY].name, pstNotify->strKey);
	}
	blobmsg_add_string(buf,term_email_policy[_EMAIL_INFO_DIRECTION].name, pstNotify->emailType == _EMAIL_SMTP ? "s" : "r");
	blobmsg_add_string(buf,term_email_policy[_EMAIL_INFO_FROM].name, pstNotify->emailType == _EMAIL_SMTP ? pstNotify->strUser : stEmailInfo.strSender);
	blobmsg_add_string(buf,term_email_policy[_EMAIL_INFO_TO].name, pstNotify->emailType != _EMAIL_SMTP ? stEmailInfo.strTo : pstNotify->strTo);

	if(strlen(stEmailInfo.ucSubject))
	{
    	blobmsg_add_string(buf,term_email_policy[_EMAIL_INFO_SUBJECT].name, stEmailInfo.ucSubject);
	}
	if(strlen(stEmailInfo.stExtractInfo.strContentFile))
	{
    	blobmsg_add_string(buf,term_email_policy[_EMAIL_INFO_CONTENT].name, stEmailInfo.stExtractInfo.strContentFile);
	}
	if(strlen(stEmailInfo.stExtractInfo.strAttchFile))
	{
    	blobmsg_add_string(buf,term_email_policy[_EMAIL_INFO_ATTACH].name, stEmailInfo.stExtractInfo.strAttchFile);
	}
	blobmsg_close_table(buf, tbl);
	blobmsg_close_array(&ubusMsg, array);
	
	blobmsg_add_u32(&ubusMsg, term_broad_policy[_TREMINAL_COUNT].name, 1);

	fprintf(stderr, "email json: %s\n", blobmsg_format_json(ubusMsg.head, true));
	int err = ubus_notify(gctx,  &stVirtualObj, term_broad_policy[_TREMINAL_EMAIL].name, ubusMsg.head, -1); /*do not expect a response*/
	if (err)
		WARNING( "Notify failed: %s\n", ubus_strerror(err));
	#endif

}
int email_test(void)
{
	#ifndef TRAFFIC_CMCC
	SMTP_PARSE_INFO stEmailInfo;
    bzero(&stEmailInfo,sizeof(stEmailInfo));
	return parse_email("/tmp/email_tmp/email_1c1b0dacca3d_16-20-25",_EMAIL_IMAP,&stEmailInfo);
	#endif
}	