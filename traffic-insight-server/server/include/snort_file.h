/*
 * @Author: jiamu 
 * @Date: 2018-09-29 17:36:35 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-11-12 20:12:19
 */



#ifndef _IM_SNORT_FILE_H_
#define _IM_SNORT_FILE_H_

#include "im_config.h"
#include "acsmx2.h"
#include "snort_content.h"
#include "snort_engine.h"

#define PROFILE_PATH "/etc/traffic-insight/protoliszt.rule"


/**********************************************************************
 * 
 *                 下面是rule参数类型相关
 * 
*********************************************************************/

typedef struct 
{
    uint32_t  ulIpAddr;   /* IP addr */
    uint32_t  ulNetMask;   /* netmask */
    uint16_t  usLow;           /* lo  port */
    uint16_t  usHigh;         /* hi  port */

    uint32_t  ulAddrFlags; /* flag for normal/exception processing */
} NET_TUPLE_SET;

typedef enum {
	_TARGET_RECORD_MIN = 0,
	_TARGET_QQ = _TARGET_RECORD_MIN,
	_TARGET_MQQ,
	_TARGET_WCHAT,
	_TARGET_ALIWX,
	_TARGET_MILIAO,
	_TARGET_WY163,
	_TARGET_QQM,
	_TARGET_M189,
	_TARGET_M139,
	_TARGET_MSINA,
	_TARGET_TY,
	_TARGET_BDTB,
	_TARGET_MPLT,
	_TARGET_TXWB,
	_TARGET_XLWB,
	_TARGET_TAOBAO,
	_TARGET_TMALL,
	_TARGET_JD,
	_TARGET_XC,
	_TARGET_QUNAR,
	_TARGET_YL,
	_TARGET_M126,
	_TARGET_FEIXIN,
	_TARGET_MOMO,
	_TARGET_VIPSHOP,
	_TARGET_MEITUAN,
	_TARGET_DIANPING,
	_TARGET_DIDI,
	_TARGET_KUAIDI,
	_TARGET_TC58,
	_TARGET_GANJI,
	_TARGET_HTTP,
	_TARGET_SMTP,
	_TARGET_IMAP4,
	_TARGET_POP3,
	_TARGET_MAX,	// max is 31
} ENUM_TARGET_TYPE;

typedef struct
{
    char strName[64];
    int  eType;
    void *extend;
}TARGET_TYPE_MAP;

#define CHECK_STREAM_ACTION(subtype,check) ((subtype) & (1 << (check)))
#define SET_STREAM_ACTION(check) (1 << check)

typedef enum
{
	_STREAM_GATHER_BASE = 0,
	_STREAM_GATHER_HTTP,
	_STREAM_NO
}STREAM_ACTION;
/*************************************************************************
 * 
 *                  下面是RULE文件相关
 * 
*************************************************************************/
typedef struct
{
    NET_TUPLE_SET stSrcInfo;
    NET_TUPLE_SET stDstInfo;
   
    uint16_t	dlenl;
	uint16_t	dlenh;           /*data len*/

    uint32_t proto:8;			 /* protocol */
	uint32_t n_port_s:1;		 /* not source port flag */
	uint32_t n_port_d:1;		 /* not dest port flag */
	uint32_t any_port_s:1;      /* any source port flag */
	uint32_t any_port_d:1;      /* any dest port flag */
	uint32_t n_ip_s:1;			 /* not source ip flag */
	uint32_t n_ip_d:1;			 /* not dest ip flag */
	uint32_t any_ip_s:1;		 /* any source ip flag */
	uint32_t any_ip_d:1;		 /* any dest ip flag */
	uint32_t b_bdir:1;			 /* both directional. */
	uint32_t chk_hdr_only:1;	 /* check header only. */
	
}RULE_HEAD_INFO;


typedef struct
{
    char strOptName[64];
    char strOptVal[256];
    struct list_head list;
    /*may need callback*/
}RULE_OPTION_INFO;

/**
 * @brief 
 * 	一个content由多个option组成
 */
typedef struct{
	
   	u_int16_t offset;             /* pattern search start offset */
	u_int16_t eoffset;			  /* pattern search start from end of payload offset */
    u_int16_t depth;              /* pattern search depth */
    u_int16_t distance;           /* offset to start from based on last match */

	u_int16_t rawbytes:1;           /* Search the raw bytes rather than any decoded app buffer */

    u_int16_t nocase:1;             /* Toggle case insensitity */
	u_int16_t use_doe:1;            /* Use the doe_ptr for relative pattern searching */
	u_int16_t n_content:1;			/* match not current content. */
	u_int16_t use_record:1;			/* record current ptr. */
	u_int16_t do_or:1;				/* or. */
	u_int16_t record_oft:8;			/* record current ptr offset. */

	int (*search)(char *data, int len, void *this);  /* search function */
    int *skip_stride;			/* B-M skip array */
    int *shift_stride;			/* B-M shift array */

	u_int16_t pattern_size;    		/* size of app layer pattern */
	char pattern_buf[0];		/* app layer pattern to match on */

	struct list_head list;
} RULE_CONTENT_INFO;
/**
 * @brief 
 *  target setmark 100
 *  target RECORD QQ
 */
typedef enum
{
    _ACTION_UNSPEC = 0,
	_ACTION_MARK,
	_ACTION_DROP,
	_ACTION_RECORD,
	_ACTION_MAX,
}RULE_ACTION;

typedef struct
{
    char strName[32];
    int  eAction;
    //int  eType;
	const TARGET_TYPE_MAP *pstTargetMap;
    /*may need callback*/
}RULE_TARGET_INFO;

typedef struct
{
    RULE_HEAD_INFO   stRuleHeadInfo;
    struct list_head listOption;                     /*for RULE_OPTION_INFO*/
	//struct list_head listContent;					 /*for RULE_CONTENT_INFO*/
    RULE_TARGET_INFO stTargetInfo;
    struct list_head listRule;                      /*for rule self*/
	void			*ds_list[RESV_MAX];             /*pstContentMatch list*/
}RULE_DETAIL_INFO;

typedef struct
{   
	char strRuleInfo[64];
	RULE_DETAIL_INFO *pstRuleHead;
}CHECK_RULE_INFO;

int snort_init_file(const char *file);
#endif
