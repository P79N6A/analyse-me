/*
 * @Author: jiamu 
 * @Date: 2018-10-29 10:36:27 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-29 20:59:32
 */
#include "snort_http.h"

#include <assert.h>
#include "snort_file.h"
#include "list.h"
#include "record_data.h"
#include "protocol.h"
#include "cJSON.h"
#include "log.h"
#ifndef TRAFFIC_CMCC
#include "http_parser.h"
#undef TRUE
#define TRUE 1
#undef FALSE
#define FALSE 0

#define HTTP_PORT 80

#define MAX_HEADERS 20
#define MAX_ELEMENT_SIZE 2048
#define MAX_CHUNKS 16

#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define MAX_MESSAGES     5

//#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))
#define HTTP_OVER_TIME 7

struct message {
  const char *name; // for debugging purposes
  const char *raw;
  enum http_parser_type type;
  enum http_method method;
  int status_code;
  char response_status[MAX_ELEMENT_SIZE];
  char request_path[MAX_ELEMENT_SIZE];
  char request_url[MAX_ELEMENT_SIZE];
  char fragment[MAX_ELEMENT_SIZE];
  char query_string[MAX_ELEMENT_SIZE];
  char body[MAX_ELEMENT_SIZE];
  size_t body_size;
  const char *host;
  const char *userinfo;
  uint16_t port;
  int num_headers;
  enum { NONE=0, FIELD, VALUE } last_header_element;
  char headers [MAX_HEADERS][2][MAX_ELEMENT_SIZE];
  int should_keep_alive;

  int num_chunks;
  int num_chunks_complete;
  int chunk_lengths[MAX_CHUNKS];

  const char *upgrade; // upgraded body

  unsigned short http_major;
  unsigned short http_minor;

  int message_begin_cb_called;
  int headers_complete_cb_called;
  int message_complete_cb_called;
  int status_cb_called;
  int message_complete_on_eof;
  int body_is_final;
};

#define HTTP_FILTER_FILE "/etc/traffic-insight/http_filter.json"
typedef struct
{
	char strFilter[16];
	struct list_head list;
}HTTP_FILTER_INFO;

extern void record_http_cb(struct ev_loop *loop, ev_timer *watcher, int revents);
static struct list_head stFilterList;
static struct list_head stHttpList;
static struct list_head stFindList;
static http_parser *parser;
static int num_messages;
static struct message messages[MAX_MESSAGES];
static int currently_parsing_eof;
static ev_timer http_watcher;

/* strnlen() is a POSIX.2008 addition. Can't rely on it being available so
 * define it ourselves.
 */
size_t
strnlen(const char *s, size_t maxlen)
{
	const char *p;

	p = memchr(s, '\0', maxlen);
	if (p == NULL)
		return maxlen;

	return p - s;
}

size_t strlncat(char *dst, size_t len, const char *src, size_t n)
{
	size_t slen;
	size_t dlen;
	size_t rlen;
	size_t ncpy;

	slen = strnlen(src, n);
	dlen = strnlen(dst, len);

	if (dlen < len) 
	{
		rlen = len - dlen;
		ncpy = slen < rlen ? slen : (rlen - 1);
		memcpy(dst + dlen, src, ncpy);
		dst[dlen + ncpy] = '\0';
	}

	assert(len > slen + dlen);
	return slen + dlen;
}

size_t
strlncpy(char *dst, size_t len, const char *src, size_t n)
{
	size_t slen;
	size_t ncpy;

	slen = strnlen(src, n);

	if (len > 0) 
	{
		ncpy = slen < len ? slen : (len - 1);
		memcpy(dst, src, ncpy);
		dst[ncpy] = '\0';
	}

	assert(len > slen);
	return slen;
}

int message_begin_cb (http_parser *p)
{
	assert(p == parser);
	if(num_messages == MAX_MESSAGES || messages[num_messages].message_begin_cb_called == TRUE)
	{
		num_messages = num_messages == MAX_MESSAGES ? (MAX_MESSAGES - 1) : num_messages;
		bzero(&messages[num_messages],sizeof(messages[num_messages]));
		messages[num_messages].message_begin_cb_called = FALSE;
	}
	assert(!messages[num_messages].message_begin_cb_called);
	messages[num_messages].message_begin_cb_called = TRUE;

	return 0;
}

/**
 * @brief 
 * 	解析头部的域名称
 * @param p 
 * @param buf 
 * @param len 
 * @return int 
 */
int header_field_cb (http_parser *p, const char *buf, size_t len)
{
    
	assert(p == parser);
	struct message *m = &messages[num_messages];

	if (m->last_header_element != FIELD)
	m->num_headers++;
	if(m->num_headers > MAX_HEADERS)
	{
		return -1;
	}
	strlncat(m->headers[m->num_headers-1][0],
			sizeof(m->headers[m->num_headers-1][0]),
			buf,
			len);

	m->last_header_element = FIELD;
	//printf("%s :buf-->%s \n",__FUNCTION__,m->headers[m->num_headers-1][0]);

	return 0;
}
/**
 * @brief 
 * 	解析头部域的值
 * @param p 
 * @param buf 
 * @param len 
 * @return int 
 */
int header_value_cb (http_parser *p, const char *buf, size_t len)
{
	
	assert(p == parser);
	struct message *m = &messages[num_messages];

	strlncat(m->headers[m->num_headers-1][1],
			sizeof(m->headers[m->num_headers-1][1]),
			buf,
			len);

	m->last_header_element = VALUE;
	//printf("%s :buf-->%s \n",__FUNCTION__,m->headers[m->num_headers-1][1]);

	return 0;
}
/**
 * @brief 
 * 解析Url
 * @param p 
 * @param buf 
 * @param len 
 * @return int 
 */
int request_url_cb (http_parser *p, const char *buf, size_t len)
{
	
	assert(p == parser);
	strlncat(messages[num_messages].request_url,
			sizeof(messages[num_messages].request_url),
			buf,
			len);
	//printf("%s :buf-->%s \n",__FUNCTION__,messages[num_messages].request_url);
	return 0;
}
/**
 * @brief 
 * 	解析状态码
 * @param p 
 * @param buf 
 * @param len 
 * @return int 
 */
int response_status_cb (http_parser *p, const char *buf, size_t len)
{
	//printf("%s enter \n",__FUNCTION__);
	assert(p == parser);

	messages[num_messages].status_cb_called = TRUE;

	strlncat(messages[num_messages].response_status,
			sizeof(messages[num_messages].response_status),
			buf,
			len);
	//printf("%s :buf-->%s \n",__FUNCTION__,messages[num_messages].response_status);

  	return 0;
}

void check_body_is_final (const http_parser *p)
{

	if (messages[num_messages].body_is_final) 
	{
		fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
						"on last on_body callback call "
						"but it doesn't! ***\n\n");
		// assert(0);
		// abort();
		return;
	}
	messages[num_messages].body_is_final = http_body_is_final(p);
}

int body_cb (http_parser *p, const char *buf, size_t len)
{
	assert(p == parser);
	strlncat(messages[num_messages].body,
			sizeof(messages[num_messages].body),
			buf,
			len);
	messages[num_messages].body_size += len;
	check_body_is_final(p);
	//printf("%s :buf-->%s \n",__FUNCTION__,messages[num_messages].body); /*body不一定可见*/
	//printf("body_cb: '%s'\n", requests[num_messages].body);
	return 0;
}
/**
 * @brief 
 * 	头部处理完成
 * @param p 
 * @return int 
 */
int headers_complete_cb (http_parser *p)
{

	assert(p == parser);
	messages[num_messages].method = parser->method;
	messages[num_messages].status_code = parser->status_code;
	messages[num_messages].http_major = parser->http_major;
	messages[num_messages].http_minor = parser->http_minor;
	messages[num_messages].headers_complete_cb_called = TRUE;
	messages[num_messages].should_keep_alive = http_should_keep_alive(parser);
	
  	return 0;
}

int message_complete_cb (http_parser *p)
{
	assert(p == parser);
	if (messages[num_messages].should_keep_alive != http_should_keep_alive(parser))
	{
		fprintf(stderr, "\n\n *** Error http_should_keep_alive() should have same "
						"value in both on_message_complete and on_headers_complete "
						"but it doesn't! ***\n\n");
		// assert(0);
		// abort();
	}

	if (messages[num_messages].body_size &&
		http_body_is_final(p) &&
		!messages[num_messages].body_is_final)
	{
		fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
						"on last on_body callback call "
						"but it doesn't! ***\n\n");
		// assert(0);
		// abort();
	}

	messages[num_messages].message_complete_cb_called = TRUE;

	messages[num_messages].message_complete_on_eof = currently_parsing_eof;

	num_messages++;
	
  return 0;
}

int chunk_header_cb (http_parser *p)
{
	
	assert(p == parser);
	int chunk_idx = messages[num_messages].num_chunks;
	messages[num_messages].num_chunks++;
	if (chunk_idx < MAX_CHUNKS) {
	messages[num_messages].chunk_lengths[chunk_idx] = p->content_length;
	}
	
  	return 0;
}
int chunk_complete_cb (http_parser *p)
{
	//printf("%s enter \n",__FUNCTION__);
  	assert(p == parser);

	/* Here we want to verify that each chunk_header_cb is matched by a
	* chunk_complete_cb, so not only should the total number of calls to
	* both callbacks be the same, but they also should be interleaved
	* properly */
	assert(messages[num_messages].num_chunks ==
			messages[num_messages].num_chunks_complete + 1);

	messages[num_messages].num_chunks_complete++;
	//printf("%s exit \n",__FUNCTION__);
	
  	return 0;
}

static http_parser_settings settings =
  {.on_message_begin = message_begin_cb
  ,.on_header_field = header_field_cb
  ,.on_header_value = header_value_cb
  ,.on_url = request_url_cb
  ,.on_status = response_status_cb
  ,.on_body = body_cb
  ,.on_headers_complete = headers_complete_cb
  ,.on_message_complete = message_complete_cb
  ,.on_chunk_header = chunk_header_cb
  ,.on_chunk_complete = chunk_complete_cb
  };
#if 0
static void handle_http_cb(struct ev_loop *loop, ev_timer *watcher, int revents)
{

	record_http_cb(loop,watcher,revents);

	HTTP_URL_INFO *pstOptionTmp = NULL;
    HTTP_URL_INFO *pstOptionPos = NULL;

	list_for_each_entry_safe(pstOptionTmp,pstOptionPos,&stHttpList,list)
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
		do_update_url(pstOptionTmp);

		list_del(&pstOptionTmp->list);
        free(pstOptionTmp);
		pstOptionTmp = NULL;
	}
}
#endif

int http_filter_init(void)
{
	init_list_head(&stFilterList);

	if(access(HTTP_FILTER_FILE,R_OK) != 0)
    {
        printf("No input data \n");
        return RET_FILEERR;
    }
    struct stat stFileInfo;
    memset(&stFileInfo,0,sizeof(stFileInfo));

    if (stat(HTTP_FILTER_FILE, &stFileInfo) < 0) 
    {
        return RET_FILEERR;
    }

    unsigned char *ucFileData = (unsigned char *)calloc(1,stFileInfo.st_size + 128);
    if(ucFileData == NULL)
    {
        return RET_FILEERR;
    }
    bzero(ucFileData,stFileInfo.st_size + 128);

    int fd = open(HTTP_FILTER_FILE,O_RDONLY);
    if(fd < 0)
    {
        free(ucFileData);
        return RET_FILEERR;
    }
    read(fd,ucFileData,stFileInfo.st_size);
    close(fd);

	cJSON *root = cJSON_Parse((char *)ucFileData);
    if(NULL == root)
    {
        printf("Error before: [%s]\n",cJSON_GetErrorPtr());
        free(ucFileData);
        return -1;
    }
	cJSON *nameJson     = cJSON_GetObjectItem(root,"name");
	printf("http filter info name %s \n",nameJson ? nameJson->valuestring : "unknown");
	cJSON *ruleJson  = cJSON_GetObjectItem(root,"rule");
    if(NULL == ruleJson)
    {
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
        free(ucFileData);
        return -1;
    }

	int i = 0;
	int ruleNums = cJSON_GetArraySize(ruleJson);
	HTTP_FILTER_INFO stFilterTmp;
	HTTP_FILTER_INFO *pstFilterInfo = NULL;
	for(i = 0;i < ruleNums;i++)
	{
		cJSON *objectJson = cJSON_GetArrayItem(ruleJson,i);
		if(!objectJson)
        {
            free(ucFileData);
       	 	return -1;
        }
		memset(&stFilterTmp,0,sizeof(stFilterTmp));
		cJSON *suffixJson = cJSON_GetObjectItem(objectJson,"suffix");
		if(!suffixJson)
        {
            free(ucFileData);
       	 	return -1;
        }
		strncpy(stFilterTmp.strFilter,suffixJson->valuestring,sizeof(stFilterTmp.strFilter));
		pstFilterInfo = calloc(1,sizeof(HTTP_FILTER_INFO));
		if(pstFilterInfo == NULL)
		{
			fatal("Now get mem failed \n");
		}
		memcpy(pstFilterInfo,&stFilterTmp,sizeof(HTTP_FILTER_INFO));
		printf("Filter suffix-->%s \n",pstFilterInfo->strFilter);
		init_list_head(&pstFilterInfo->list);
		list_insert_tail(&pstFilterInfo->list,&stFilterList);
	}

	free(ucFileData);
	ucFileData = NULL;

	return RET_SUCCESS;
}
int http_insight_init(void *loop)
{	
	#ifndef TRAFFIC_CMCC
	unsigned long version;
	unsigned major;
	unsigned minor;
	unsigned patch;
	
    version = http_parser_version();
    major = (version >> 16) & 255;
    minor = (version >> 8) & 255;
    patch = version & 255;
    printf("http_parser v%u.%u.%u (0x%06lx)\n", major, minor, patch, version);

    parser = calloc(1,sizeof(http_parser));
    if(NULL == parser)
    {
        return RET_FAILED;
    }
    memset(parser,0,sizeof(http_parser));
	//parser.data = 
	init_list_head(&stHttpList);
	init_list_head(&stFindList);

	http_filter_init();

	http_watcher.data = &stHttpList;

	ev_timer_init(&http_watcher, record_http_cb, 0, 7);
	ev_timer_start(loop, &http_watcher);
	#endif
	
    return RET_SUCCESS;
}
/**
 * @brief 
 * 	将已经解析好的message进行分析处理
 * 	其实http1.1是串行操作的
 *  一条请求就对应一条回复
 *  处理回复之后才写一次请求
 * @param addr 
 * @param pstEthInfo 
 * @param direction 
 * @param pstConn 
 * @return int 
 */
int do_handle_message(struct tuple4 *addr,struct ethhdr *pstEthInfo,int direction,void *Conn)
{
	
	int i = 0,flg = 0;
	char strHost[128] = {0};
	char strUrl[512] = {0};
	// HTTP_URL_INFO *pstOptionTmp = NULL;
	// HTTP_URL_INFO *pstOptionPos = NULL;

	//m_priv_t *pstPri			= ( m_priv_t *)pri;
	NIDS_CONNTRACK_RECORD *pstConn =  (NIDS_CONNTRACK_RECORD *)Conn;

	if(IP_CT_DIR_ORIGINAL == direction)
	{
		/**
		 * @brief 
		 * 这不能这样，因为有可能url很长，关键字被夹在中间
		 */
		// for(i = 0;i < ARRAY_SIZE(strSuffix);i++)
		// {
		// 	if((tmp = strstr(messages[0].request_url,strSuffix[i])) != NULL)
		// 	{
		// 		tmp += strlen(strSuffix[i]);
		// 		flg = tmp - messages[0].request_url;
		// 		strncpy(strUrl,messages[0].request_url,flg < ARRAY_SIZE(strUrl) ? flg : ARRAY_SIZE(strUrl));
		// 		printf("Match suffix %s len :%d  \n",strSuffix[i],flg);
		// 		break;
		// 	}
		// }
		char *strUriTmp = NULL;
		int len = 0;
		HTTP_FILTER_INFO *pstRuleTmp   = NULL;
		strUriTmp = strchr(messages[0].request_url,'?');
		
		len = strUriTmp ? (strUriTmp - messages[0].request_url) : strlen(messages[0].request_url);
		strncpy(strUrl,messages[0].request_url, len < ARRAY_SIZE(strUrl) ? len : ARRAY_SIZE(strUrl));
		
		/**
		 * @brief Construct a new list for each entry object
		 * 
		 */
		list_for_each_entry(pstRuleTmp,&stFilterList,list)
		{
			if(strstr(strUrl,pstRuleTmp->strFilter))
				return RET_SUCCESS;
		}

		for(i = 0;i < MAX_HEADERS && strlen(messages[0].headers[i][0]) != 0;i++)
		{
			if(strcasecmp(messages[0].headers[i][0],"host") == 0)
			{
				
				strncpy(strHost,messages[0].headers[i][1],ARRAY_SIZE(strHost));
				//printf("Now get host-->%s  \n",strHost);
				continue;
			}
			if(strcasecmp(messages[0].headers[i][0],"Origin") == 0)
			{
				memset(strHost,0,ARRAY_SIZE(strHost));
				strncpy(strHost,messages[0].headers[i][1],ARRAY_SIZE(strHost));
				//printf("Now get Origin-->%s  \n",strHost);
				break;
			}
		}
		//printf("row url --> %s\n",messages[0].request_url);
		if(strlen(strHost) && strlen(strUrl))
		{
			#if 0
			list_for_each_entry_safe(pstOptionTmp,pstOptionPos,&stFindList,list)
			{
				if(!CHECK_STREAM_ACTION(pstConn->eSubType,_STREAM_GATHER_HTTP))    /*避免浏览器的多线程访问同一个uri*/
				{
					if(memcmp(pstOptionTmp->ucMacAddr,pstEthInfo->h_source,6) == 0 && 
					// memcmp(&pstOptionTmp->addr,addr,sizeof(pstOptionTmp->addr)) == 0  &&  /*本地有可能是开多个句柄处理的，源端口可能会有多个*/
					pstOptionTmp->addr.daddr == addr->daddr &&
					pstOptionTmp->addr.dest  == addr->dest &&
					strcmp(pstOptionTmp->strUrl,strUrl) == 0 &&
					strcmp(pstOptionTmp->strHost,strHost) == 0
					)
					return RET_SUCCESS;
				}
				else /*避免同一链接中缓存了两条记录*/
				{
					if(memcmp(pstOptionTmp->ucMacAddr,pstEthInfo->h_source,6) == 0 && 
				 	  memcmp(&pstOptionTmp->addr,addr,sizeof(pstOptionTmp->addr)) == 0  
					)
					{
						list_del(&pstOptionTmp->list);
						free(pstOptionTmp);
						pstOptionTmp = NULL;
						break;
					}
				}
			}

			HTTP_URL_INFO *pstTmp = calloc(1,sizeof(HTTP_URL_INFO));
			if(NULL == pstTmp)
			{
				return RET_FAILED;
			}
			memset(pstTmp,0,sizeof(HTTP_URL_INFO));
			init_list_head(&pstTmp->list);
			strncpy(pstTmp->strHost,strHost,ARRAY_SIZE(pstTmp->strHost));
			strncpy(pstTmp->strUrl,strUrl,ARRAY_SIZE(pstTmp->strUrl));
			pstTmp->addr = *addr;
			pstTmp->ulTime = time(NULL);

			memcpy(pstTmp->ucMacAddr,pstEthInfo->h_source,6);
			
			// printf("!!!!!!!!!%02x:%02x:%02x:%02x:%02x:%02x src:%08x %d dst:%08x %d %s%s \n",
			// pstTmp->ucMacAddr[0],pstTmp->ucMacAddr[1],pstTmp->ucMacAddr[2],
			// pstTmp->ucMacAddr[3],pstTmp->ucMacAddr[4],pstTmp->ucMacAddr[5],
			// pstTmp->addr.saddr,pstTmp->addr.source,pstTmp->addr.daddr,pstTmp->addr.dest,strHost,strUrl
			// );

			list_insert_tail(&pstTmp->list,&stFindList);
			pstConn->eSubType  |= SET_STREAM_ACTION(_STREAM_GATHER_HTTP);

			#else
			HTTP_URL_INFO *pstTmp = calloc(1,sizeof(HTTP_URL_INFO));
			if(NULL == pstTmp)
			{
				return RET_FAILED;
			}
			memset(pstTmp,0,sizeof(HTTP_URL_INFO));
			//init_list_head(&pstTmp->list);
			strncpy(pstTmp->strHost,strHost,ARRAY_SIZE(pstTmp->strHost));
			strncpy(pstTmp->strUrl,strUrl,ARRAY_SIZE(pstTmp->strUrl));
			pstTmp->addr = *addr;
			pstTmp->ulTime = time(NULL);

			memcpy(pstTmp->ucMacAddr,pstEthInfo->h_source,6);
			
			// printf("!!!!!!!!!%02x:%02x:%02x:%02x:%02x:%02x src:%08x %d dst:%08x %d %s%s \n",
			// pstTmp->ucMacAddr[0],pstTmp->ucMacAddr[1],pstTmp->ucMacAddr[2],
			// pstTmp->ucMacAddr[3],pstTmp->ucMacAddr[4],pstTmp->ucMacAddr[5],
			// pstTmp->addr.saddr,pstTmp->addr.source,pstTmp->addr.daddr,pstTmp->addr.dest,strHost,strUrl
			// );
			//list_insert_tail(&pstTmp->list,&stFindList);
			
			if(pstConn->ucData)
			{
				//printf("FreeMem --> Line = %d pstConn->ucData = %p \n",__LINE__,pstConn->ucData);
				free(pstConn->ucData);
			}
			//printf("AllocMem--> Line = %d pstTmp = 0x%p \n",__LINE__,pstTmp);
			pstConn->ucData = pstTmp;
			pstConn->eSubType  |= SET_STREAM_ACTION(_STREAM_GATHER_HTTP);

			#endif
		}
		//printf("Now get host-->%s%s  \n",strHost,strUrl);
	}
	else
	{	
		//uint32_t ulNowTime = time(NULL);

		//printf("Now get response \n");
		for(i = 0;i < MAX_HEADERS && strlen(messages[0].headers[i][0]) != 0;i++)
		{
			if(strcasecmp(messages[0].headers[i][0],"Content-Type") == 0)
			{
				//printf("Content-type-->%s \n",messages[0].headers[i][1]);
				if(strstr(messages[0].headers[i][1],"text/html") != NULL ||
				  strstr(messages[0].headers[i][1],"text/xml") != NULL) 
				{
					flg = 1;
					//printf("****************************************************\n");
					break;
				}
				
			}
		}
		#if 1
		
		HTTP_URL_INFO *pstTmp = (HTTP_URL_INFO *)pstConn->ucData;
		if(NULL == pstTmp)
		{
			return RET_FAILED;
		}
		init_list_head(&pstTmp->list);
		pstTmp->ulTime = time(NULL);
		
		// printf("!!!!!!*22**********!!!%02x:%02x:%02x:%02x:%02x:%02x src:%08x %d dst:%08x %d %s%s \n",
		// pstTmp->ucMacAddr[0],pstTmp->ucMacAddr[1],pstTmp->ucMacAddr[2],
		// pstTmp->ucMacAddr[3],pstTmp->ucMacAddr[4],pstTmp->ucMacAddr[5],
		// pstTmp->addr.saddr,pstTmp->addr.source,pstTmp->addr.daddr,pstTmp->addr.dest,strHost,strUrl
		// );

		//printf("FreeMem --> Line = %d pstConn->ucData = %p \n",__LINE__,pstConn->ucData);

		if(flg)
			list_insert_tail(&pstTmp->list,&stHttpList);
		else
			free(pstConn->ucData);
	
		pstConn->eSubType  &= ~SET_STREAM_ACTION(_STREAM_GATHER_HTTP);
		//free(pstConn->ucData);
		pstConn->ucData = NULL;
		#else
		//if(flg)
		{
			// printf("new flg %d***************%02x:%02x:%02x:%02x:%02x:%02x src:%08x %d dst:%08x %d \n",flg,
			// pstEthInfo->h_dest[0],pstEthInfo->h_dest[1],pstEthInfo->h_dest[2],
			// pstEthInfo->h_dest[3],pstEthInfo->h_dest[4],pstEthInfo->h_dest[5],
			// addr->saddr,addr->source,addr->daddr,addr->dest
			// );

			list_for_each_entry_safe(pstOptionTmp,pstOptionPos,&stFindList,list)
			{
				// printf("row ***************%02x:%02x:%02x:%02x:%02x:%02x src:%08x %d dst:%08x %d \n",
				// pstOptionTmp->ucMacAddr[0],pstOptionTmp->ucMacAddr[1],pstOptionTmp->ucMacAddr[2],
				// pstOptionTmp->ucMacAddr[3],pstOptionTmp->ucMacAddr[4],pstOptionTmp->ucMacAddr[5],
				// pstOptionTmp->addr.saddr,pstOptionTmp->addr.source,pstOptionTmp->addr.daddr,pstOptionTmp->addr.dest
				// );
			
				if(memcmp(pstOptionTmp->ucMacAddr,pstEthInfo->h_dest,6) == 0 && 
				  pstOptionTmp->addr.saddr  == addr->daddr &&
				  pstOptionTmp->addr.source == addr->dest  &&
				  pstOptionTmp->addr.daddr  == addr->saddr  &&
				  pstOptionTmp->addr.dest   == addr->source
				  )
				{
					pstConn->eSubType  &= ~SET_STREAM_ACTION(_STREAM_GATHER_HTTP);
					list_del(&pstOptionTmp->list);
					if(flg)
					{
						snprintf(strUrl,ARRAY_SIZE(strUrl),"%s%s",pstOptionTmp->strHost,pstOptionTmp->strUrl);
						//printf("Find one matched flg %d  %s%s \n",flg,pstOptionTmp->strHost,pstOptionTmp->strUrl);
						list_insert_tail(&pstOptionTmp->list,&stHttpList);
					}
					else
					{
						free(pstOptionTmp);
						pstOptionTmp = NULL;
					}
					break;
				}

				if(ulNowTime > (pstOptionTmp->ulTime + HTTP_OVER_TIME))
				{
					pstConn->eSubType  &= ~SET_STREAM_ACTION(_STREAM_GATHER_HTTP);
					list_del(&pstOptionTmp->list);
					free(pstOptionTmp);
					pstOptionTmp = NULL;
				}
			}
		}
		#endif
	}
	
	return RET_FAILED;
}
/**
 * @brief 
 * 不在规则中处理
 * @param pri 
 * @return int 
 */
int start_insight_http(void *pri)
{
	return RET_FAILED;
}
/**
 * @brief 
 *  这里只解析http报文
 *  并且目前只处理html类型的url部分
 *  即获取上网地址和ip
 * @param data 
 * @param slDataLen 
 * @param slProtocol 
 * @param addr 
 * @param pstEthInfo 
 * @param direction 
 * @param pstConn 
 * @return int 
 */
int do_insight_http(void *data,int slDataLen,int slProtocol,
	struct tuple4 *addr,struct ethhdr *pstEthInfo,int direction,NIDS_CONNTRACK_RECORD *pstConn)
//int do_insight_http(void *pri)
{

	//printf("--LINE--%d \n",__LINE__);

	// m_priv_t *pstPri			= ( m_priv_t *)pri;
	// void *data 					= pstPri->data;
	// int slDataLen 				= pstPri->dlen;
	// struct tuple4 *addr			= &pstPri->ht;
	// struct ethhdr *pstEthInfo	= &pstPri->stEthInfo;
	// int direction               = pstPri->slDir;
	// NIDS_CONNTRACK_RECORD *pstConn =  (NIDS_CONNTRACK_RECORD *)pstPri->pstconn;

	//printf("!!!!!!!!!!!!!!direction->%d src-->%04x,dst-->%04x\n",direction,addr->saddr,addr->daddr);
    if(//slProtocol != IPPROTO_TCP || 
       (direction == IP_CT_DIR_ORIGINAL && addr->dest != HTTP_PORT) ||
       (direction == IP_CT_DIR_REPLY    && addr->source != HTTP_PORT)
       )
    {
        return RET_FAILED;
    }

	if( IP_CT_DIR_REPLY == direction && 
		(CONN_MAIN_INVALID != pstConn->eMainType  ||
		!CHECK_STREAM_ACTION(pstConn->eSubType,_STREAM_GATHER_HTTP))
		)
	{
		//printf("This stream base info is gathered,type is %d %d  \n",pstConn->eMainType,pstConn->eSubType);
		return RET_SUCCESS;
	}
	
	num_messages = 0;
    //printf("Now need handle http stream slDataLen = %d \n",slDataLen);
    bzero(messages,sizeof(messages));
	//messages[num_messages].message_begin_cb_called = FALSE;
    //http_parser_init(parser, direction == IP_CT_DIR_ORIGINAL ? HTTP_REQUEST : HTTP_RESPONSE);
    http_parser_init(parser, HTTP_BOTH);
	//printf("%s \n\n",IP_CT_DIR_ORIGINAL == direction ? "00000000000000000000000000000000" : "1111111111111111111111111111111111");
    size_t nparsed = http_parser_execute(parser, &settings, data, slDataLen);
    //printf("nparsed = %d slDataLen = %d \n",nparsed,slDataLen);

	/**
	 * @brief Construct a new if object
	 * 目前只处理get的request
	 */
	if(nparsed == slDataLen)
	{
		if(IP_CT_DIR_ORIGINAL == direction && messages[0].method != HTTP_GET)
			return RET_SUCCESS;
		if(IP_CT_DIR_REPLY == direction && (messages[0].status_code < 200 || messages[0].status_code > 299))
			return RET_SUCCESS;
		//printf("Handle http stream ok direction %d \n status %d \n method-->%s \n \n",direction,messages[0].status_code,IP_CT_DIR_ORIGINAL == direction ? http_method_str(messages[0].method) : "response");
		return do_handle_message(addr,pstEthInfo,direction,pstConn);
	}
    return RET_FAILED;
}
#else
int do_insight_http(void *data,int slDataLen,int slProtocol,
	struct tuple4 *addr,struct ethhdr *pstEthInfo,int direction,NIDS_CONNTRACK_RECORD *pstConn)
{
	return RET_FAILED;
}
int http_insight_init(void *loop)
{
	
}
#endif