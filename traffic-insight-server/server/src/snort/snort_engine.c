/*
 * @Author: jiamu 
 * @Date: 2018-10-09 14:54:17 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-30 19:38:05
 */

#include "snort_engine.h"
#include "snort_file.h"
#include "log.h"
#include "protocol.h"
#include "snort_http.h"
#include "snort_email.h"
#if 1


#define in_bounds(s,e,p)	(p >= s && p < e)

typedef  unsigned char u8;
typedef  unsigned int  u32;
typedef  unsigned int  __u32;

/* An arbitrary initial parameter */
#define JHASH_INITVAL		0xdeadbeef
/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> (32 - shift));
}


#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

/* jhash_3words - hash exactly 3, 2 or 1 word(s) */
static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	a += JHASH_INITVAL;
	b += JHASH_INITVAL;
	c += initval;

	__jhash_final(a, b, c);

	return c;
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
	return jhash_3words(a, 0, 0, initval);
}

#endif


#define TIMEOUT_PTLT	(5*HZ)

typedef enum {
	GRP_UNSPEC,
	GRP_SRC,
	GRP_DST,
	GRP_GENERIC,
} grp_type_t;

#define PROT_HASH_NUM			(8)
#define PROT_HASH_SZIE 			(1<<PROT_HASH_NUM)
#define PORT_HASH_MASK			(PROT_HASH_SZIE - 1)


typedef struct _port_node {
	struct _port_node *next;
	resv_type_t type;
	void *pat;
	void *pstRuleDetail;
} pat_node_t;

typedef struct _rncontent {
	struct _rncontent *next;
	void *pstRuleDetail;
} rncontent_t;

typedef struct _port_grp {
	struct hlist_node hlist;
	pat_node_t *head;
	pat_node_t *cur;
	void *pat_match;
#ifdef PTLT_SUPPORT_RNC
	rncontent_t *r_nh;
	rncontent_t *r_nc;
	u_int16_t ncrule;
#endif
	u_int16_t port;
	u_int16_t nrule;
} port_grp_t;


typedef struct _port_list {
	u_int32_t n_generic;
	u_int32_t n_src;
	u_int32_t n_dst;

	port_grp_t grc;/* a little ugly. */
	struct hlist_head src[PROT_HASH_SZIE];
	struct hlist_head dst[PROT_HASH_SZIE];
} port_list_t;




typedef int		(*pat_cpl_t)(port_grp_t * pg, pat_arm_type_t type,
							void *ct, void *pt);

static port_list_t *TCP_tree ;
static port_list_t *UDP_tree ;
static port_list_t *IP_tree  ;

static u_int32_t fdb_salt;

static inline int
match_compile(port_grp_t * pg, pat_arm_type_t type);
static inline int
match_add_pat(port_grp_t * pg, pat_arm_type_t type, void *ct, void *pt);
static inline int
match_new(port_grp_t * pg, pat_arm_type_t type);


static inline u_int32_t
port_hash(const u_int16_t port)
{
	return jhash_1word(( u_int32_t)port, fdb_salt) & PORT_HASH_MASK;
}

/**
 * @brief 
 * 	將rule中的部分选项添加到pg中
 *  并且使用pat_node_t构成单向链表
 *  这里至少会添加第一条选项
 *  其余是有door标志的选项
 * @param r 
 * @param pg 
 * @return int 
 */
static int
addpat_content(RULE_DETAIL_INFO *r, port_grp_t *pg)
{
	RULE_CONTENT_MATCH *ct;
	pat_node_t *pn;

	if (!(ct = r->ds_list[RESV_PATTERN_MATCH]))
		goto out;

	do {
		pn = calloc(1,sizeof(pat_node_t));
		memset(pn,0,sizeof(pat_node_t));
		pn->pat = (void *)ct;
		pn->type = RESV_PATTERN_MATCH;
		pn->pstRuleDetail = r;
		pn->next = NULL;

		if (!pg->head)
		{
			//INFO("Head is not exist pg is %p \n",pg);
			pg->cur = pg->head = pn;
		}
		else 
		{
			//print("pg->port = %d pg is %p !!!!!!!!!!!!!!!!!\n",pg->port,pg);
			pg->cur->next = pn;
			pg->cur = pn;
		}

		pg->nrule++;
		ct = (RULE_CONTENT_MATCH *)ct->next; 
	} while (ct && ct->do_or);


out:
	return 0;
}

static inline int
add_rule_pat(port_grp_t *pg, RULE_DETAIL_INFO *pstRuleInfo)
{
	//resv_type_t t;

	if (pstRuleInfo->stRuleHeadInfo.chk_hdr_only) {
#ifdef PTLT_SUPPORT_RNC
		rncontent_t *rnc;

		rnc		= mmalloc(sizeof(rncontent_t));
		rnc->r	= pstRuleInfo;

		if (!pg->r_nh)
			pg->r_nc = pg->r_nh = rnc;
		else {
			pg->r_nc->next = rnc;
			pg->r_nc = rnc;
		}
		pg->ncrule++;
#endif
		goto out;
	}

	addpat_content(pstRuleInfo,pg);
	// for (t = RESV_PATTERN_MATCH; t < RESV_MAX; t++)
    // {
    //     //ptl->do_resv_pat(t, pstRuleInfo, pg);
	// 	addpat_content();
    // }
out:
	return 0;
}

static inline port_grp_t *
port_grp_new(u_int16_t port)
{
	port_grp_t *pg;

	pg = calloc(1,sizeof(port_grp_t));
	memset(pg,0,sizeof(port_grp_t));
	pg->port = port;
	pg->head = NULL;
	pg->cur  = NULL;

	return pg;
}


static inline int
add_port_hlist(struct hlist_head *h,
				u_int16_t port, RULE_DETAIL_INFO *pstRuleInfo)
{
	port_grp_t *pg = NULL;
    struct hlist_node *next, *tmp;
    hlist_for_each_entry_safe(pg,next,tmp,h, hlist) 
	//hlist_for_each_entry(pg, h, hlist)
    {
		print("Find one pg port %d \n",port);
		if (pg->port == port)
			break;
	}

	if (!pg) 
	{
		
		pg = port_grp_new(port);
		hlist_add_head(&pg->hlist, h);
		print("Need new a pg %p for port %d \n",pg,port);
	}

	add_rule_pat(pg, pstRuleInfo);

	return 0;
}


static inline int
add_port_grp( port_list_t *pl, RULE_DETAIL_INFO *pstRuleInfo,
			u_int16_t port, grp_type_t type)
{
	u_int32_t			key;
	struct hlist_head	*hh;

	switch(type) {
	case GRP_UNSPEC:
		fatal("error grp_type_t.");
		break;
	case GRP_SRC:
		key = port_hash(port);
		hh = &pl->src[key];
		pl->n_src++;
		goto hlist;
		break;
	case GRP_DST:
		key = port_hash(port);
		hh = &pl->dst[key];
		pl->n_dst++;
		goto hlist;
		break;
	case GRP_GENERIC:
		pl->n_generic++;
		goto list;
		break;
	}
hlist:
	return add_port_hlist( hh, port, pstRuleInfo);
list:
	return add_rule_pat(&pl->grc, pstRuleInfo);

	return 0;
}


static inline int
add_port_list(port_list_t *pl, RULE_DETAIL_INFO *pstRuleInfo)
{
	if (pstRuleInfo->stRuleHeadInfo.b_bdir) {
		if (pstRuleInfo->stRuleHeadInfo.stSrcInfo.usHigh && !pstRuleInfo->stRuleHeadInfo.any_port_s) {
			add_port_grp(pl, pstRuleInfo, pstRuleInfo->stRuleHeadInfo.stSrcInfo.usHigh, GRP_SRC);
			add_port_grp(pl, pstRuleInfo, pstRuleInfo->stRuleHeadInfo.stSrcInfo.usHigh, GRP_DST);
			goto out;
		}
		if (pstRuleInfo->stRuleHeadInfo.stDstInfo.usHigh && !pstRuleInfo->stRuleHeadInfo.any_port_d) {
			add_port_grp(pl, pstRuleInfo, pstRuleInfo->stRuleHeadInfo.stDstInfo.usHigh, GRP_SRC);
			add_port_grp(pl, pstRuleInfo, pstRuleInfo->stRuleHeadInfo.stDstInfo.usHigh, GRP_DST);
			goto out;
		}
	}

	if (pstRuleInfo->stRuleHeadInfo.stSrcInfo.usHigh && !pstRuleInfo->stRuleHeadInfo.any_port_s) {
		add_port_grp(pl, pstRuleInfo, pstRuleInfo->stRuleHeadInfo.stSrcInfo.usHigh, GRP_SRC);
		goto out;
	}

	if (pstRuleInfo->stRuleHeadInfo.stDstInfo.usHigh && !pstRuleInfo->stRuleHeadInfo.any_port_d) {
		add_port_grp(pl, pstRuleInfo, pstRuleInfo->stRuleHeadInfo.stDstInfo.usHigh, GRP_DST);
		goto out;
	}

	add_port_grp(pl, pstRuleInfo, 0, GRP_GENERIC);
out:
	return 0;
}


// static inline int 
// add_rule_port(RULE_DETAIL_INFO *pstRuleInfo,port_list_t *pl)
// {
// 	return add_port_list(pl, pstRuleInfo);
// }

static inline int
port_list_init(void)
{
	TCP_tree = malloc(sizeof(*TCP_tree));
    UDP_tree = malloc(sizeof(*UDP_tree));
    IP_tree  = malloc(sizeof(*IP_tree));

	memset(TCP_tree,0,sizeof(*TCP_tree));
	memset(UDP_tree,0,sizeof(*UDP_tree));
	memset(IP_tree,0,sizeof(*IP_tree));

	return 0;
}

static int
merg_grc_list(port_list_t *pl)
{
#define helper(n) ({\
	if (pl->n_##n)\
		for (i = 0, hh = &pl->n[i];\
			i < PROT_HASH_SZIE; i++, hh = &pl->n[i]) {\
			hlist_for_each_entry_safe(pg,next,tmp,hh, hlist) { \
				print("Line %d pg->nrule = %d n_generic = %d \n",__LINE__,pg->nrule,pl->n_generic); \
				if (pg->nrule && pl->n_generic) {\
					pg->cur->next = pl->grc.head;\
					pg->nrule += pl->grc.nrule;\
				}\
			}\
		}\
})
	int					i;
	port_grp_t			*pg;
	struct hlist_head	*hh;
	struct hlist_node *next, *tmp;
	
	if (!pl)
		goto out;
	
	helper(src);
	helper(dst);
out:
	return 0;
#undef helper
}

static inline int
add_match_content(port_grp_t * pg, pat_arm_type_t type,
pat_node_t *pn, pat_cpl_t fn)
{
	RULE_CONTENT_MATCH *ct = pn->pat;

	return fn(pg, type, ct, (void *)pn);
	//return fn(pg, type, ct->pattern_buf, ct->pattern_size, ct->nocase, (void *)pn);
}

static inline int
do_resv_patmatch(port_grp_t * pg, resv_type_t type,
				pat_arm_type_t arm_type, pat_node_t *pn,
				pat_cpl_t fn)
{
	// resv_t *tmp = resv_way[type];

	// if (!tmp)
	// 	fatal("unknow type:%d.", type);

	// return tmp->apm(pg, arm_type, pn, fn);
	return RET_SUCCESS;
}


static int
patternmatch_init(int slPatType, port_grp_t * pg)
{
	pat_node_t *pn;

	match_new(pg, slPatType);
	pn = pg->head;
	while(pn) {
		// do_resv_patmatch(pg, pn->type,
		// 				slPatType, pn,
		// 				(pat_cpl_t)match_add_pat);
		add_match_content(pg,slPatType,pn,(pat_cpl_t)match_add_pat);
		pn = pn->next;
	}
	return match_compile(pg, slPatType);
}


static int
rule_port_compile(int slPatType, port_list_t *pl)
{
#define helper(n) ({\
	if (pl->n_##n)\
		for (i = 0, hh = &pl->n[i];\
			i < PROT_HASH_SZIE; i++, hh = &pl->n[i]) {\
			hlist_for_each_entry_safe(pg,next,tmp,hh, hlist) { \
				if (pg->nrule && patternmatch_init(slPatType, pg)) {\
					print("RuleNum:%d \n",pg->nrule); \
					goto out;\
				}\
			}\
		}\
})
	int					i;
	port_grp_t			*pg;
	struct hlist_head	*hh;
	struct hlist_node *next, *tmp;

	if (!pl)
		goto out;

	helper(src);
	helper(dst);

	if (pl->grc.nrule
		&& patternmatch_init(slPatType, &pl->grc))
		goto out;

	return 0;
out:
	return -1;
#undef helper
}


/***************************************************************************************************
 * 
 * 							ACS 算法相關
 * 
****************************************************************************************************/

static inline int
match_new(port_grp_t * pg, pat_arm_type_t type)
{
	switch(type) {
	case PAT_ACSM2:
		pg->pat_match = (void *)acsmNew2(NULL, NULL, NULL);
		break;
	default:
		return -1;
		break;
	}
	return 0;
}


static inline int
match_compile(port_grp_t * pg, pat_arm_type_t type)
{
	switch(type) {
	case PAT_ACSM2:
		return acsmCompile2(pg->pat_match, NULL, NULL);
		break;
	default:
		return -1;
		break;
	}

	return 0;
}

static inline int
match_add_pat(port_grp_t * pg, pat_arm_type_t type, void *ct, void *pt)
{
	RULE_CONTENT_MATCH *pstContent = (RULE_CONTENT_MATCH *)ct;
	//INFO("add pat %s psize %d depth %d ",pstContent->pattern_buf, pstContent->pattern_size,pstContent->depth);
	switch(type) {
	case PAT_ACSM2:
		//return acsmAddPattern2(pg->pat_match, p, psize, nc, 0, pt,0);
		return acsmAddPattern2(pg->pat_match, (unsigned char *)pstContent->pattern_buf, pstContent->pattern_size, 
		pstContent->nocase, pstContent->offset,pstContent->depth,0, pt,0);
		break;
	default:
		return -1;
		break;
	}
	return 0;
}

static inline int
match_free(port_grp_t * pg, pat_arm_type_t type)
{
	if (!pg->pat_match)
		goto out;

	switch(type) {
	case PAT_ACSM2:
		acsmFree2(pg->pat_match);
		break;
	default:
		return -1;
		break;
	}
out:
	return 0;
}

/**
 * @brief 
 * 	将端口用于生成对应的分组
 *  并且记录下一部分规则,后面会用于acs判断
 *  可以进行一次初步过滤
 *  
 * @param pstCheckRuleInfo 
 */
void snort_create_fast_detection(CHECK_RULE_INFO *pstCheckRuleInfo,int slSize)
{
	int i = 0;
    RULE_DETAIL_INFO *pstRuleTmp   = NULL;

	for(i = 0;i < slSize;i++)
    {
        if(strcasecmp(pstCheckRuleInfo[i].strRuleInfo,"tcp") == 0)
		{
		    list_for_each_entry(pstRuleTmp,&pstCheckRuleInfo[i].pstRuleHead->listRule,listRule)
			{
				print("add tcp rule port: %d %d ,%d %d",
				pstRuleTmp->stRuleHeadInfo.stSrcInfo.usLow,pstRuleTmp->stRuleHeadInfo.stSrcInfo.usHigh,
				pstRuleTmp->stRuleHeadInfo.stDstInfo.usLow,pstRuleTmp->stRuleHeadInfo.stDstInfo.usHigh);
				add_port_list(TCP_tree,pstRuleTmp);
			}
			
		}
		else  if(strcasecmp(pstCheckRuleInfo[i].strRuleInfo,"udp") == 0)
		{
			list_for_each_entry(pstRuleTmp,&pstCheckRuleInfo[i].pstRuleHead->listRule,listRule)
			{
				print("add tcp rule port: %d %d ,%d %d",
				pstRuleTmp->stRuleHeadInfo.stSrcInfo.usLow,pstRuleTmp->stRuleHeadInfo.stSrcInfo.usHigh,
				pstRuleTmp->stRuleHeadInfo.stDstInfo.usLow,pstRuleTmp->stRuleHeadInfo.stDstInfo.usHigh);
				add_port_list(UDP_tree,pstRuleTmp);
			}
		}
		else
		{
			list_for_each_entry(pstRuleTmp,&pstCheckRuleInfo[i].pstRuleHead->listRule,listRule)
			{
				add_port_list(IP_tree,pstRuleTmp);
			}
		}

    }

	/**
	 * @brief 
	 * 	将通用链表接到源和目的后面
	 *  就相当于只有两条链表
	 */
	merg_grc_list(TCP_tree);
	merg_grc_list(UDP_tree);
	merg_grc_list(IP_tree);

	/**
	 * @brief Construct a new rule port compile object
	 * 根据前面添加的content数据
	 * 生成acs规则用于后面的数据匹配
	 */
	 rule_port_compile(PAT_ACSM2, TCP_tree);
	 rule_port_compile(PAT_ACSM2, UDP_tree);
	 rule_port_compile(PAT_ACSM2, IP_tree);
}
/**
 * @brief 
 *  生成匹配规则,主要用于acs匹配
 * @param pstRowRuleInfo 
 * @return int 
 */
int snort_make_match(void *pstRowRuleInfo,int slSize)
{
	CHECK_RULE_INFO *pstCheckRuleInfo = (CHECK_RULE_INFO *)pstRowRuleInfo;

    port_list_init();

	snort_create_fast_detection(pstCheckRuleInfo,slSize);

    return RET_SUCCESS;
}

/*********************************************************************************************
 * 
 * 						数据检测
 * 
 * 
***********************************************************************************************/
static inline port_grp_t *find_grp_port(port_list_t *pl, u_int16_t port, grp_type_t type)
{
	u_int32_t			key;
	struct hlist_head	*hh = NULL;
	port_grp_t			*pg = NULL;

	switch(type) {
	case GRP_SRC:
		key = port_hash(port);
		hh = &pl->src[key];
		break;
	case GRP_DST:
		key = port_hash(port);
		hh = &pl->dst[key];
		break;
	default:
		fatal("error grp_type_t.");
		break;
	}
	//printf("Line = %d find port %d \n",__LINE__,port);

	struct hlist_node *next, *tmp;
    hlist_for_each_entry_safe(pg,next,tmp,hh, hlist) 
	{
		//printf("pg->port = %d port = %d \n",pg->port,port);
	//hlist_for_each_entry(pg, hh, hlist) {
		if (pg->port == port)
			break;
	}

	return pg;
}


static port_grp_t * find_grp_skb(struct tuple4 *addr,int slProtocol,int direction)
{
	port_grp_t			*pg;

	switch (slProtocol) {
	case IPPROTO_TCP:
		if (!TCP_tree)
			goto out;
		return (pg = find_grp_port(TCP_tree, 
				direction == IP_CT_DIR_ORIGINAL ? addr->dest : addr->source,
				direction == IP_CT_DIR_ORIGINAL ? GRP_DST : GRP_SRC))
				? pg : &TCP_tree->grc;
		break;
	case IPPROTO_UDP:
		return (pg = find_grp_port(UDP_tree,
				direction == IP_CT_DIR_ORIGINAL ? addr->dest : addr->source,
				direction == IP_CT_DIR_ORIGINAL ? GRP_DST : GRP_SRC))
				? pg : &UDP_tree->grc;
		break;
	default:
		if (!IP_tree)
			goto out;
		return &IP_tree->grc;
		break;
	}
out:
	return NULL;
}

/****************************************************************
 *
 *  Function: mSearchCI(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring matching is case insensitive
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
static int
msearch_ci(char *buf, int blen,
		char *ptrn, int plen, int *skip, int *shift,
		m_priv_t	*pri, RULE_CONTENT_MATCH *ct)
{
    int b_idx	= plen;
#ifdef DEBUG
    int cmpcnt	= 0;
#endif
	
    if (plen == 0)
        return 1;
	
    while (b_idx <= blen) 
	{
        int p_idx = plen, skip_stride, shift_stride;

        while ((unsigned char) ptrn[--p_idx] == 
                toupper((unsigned char) buf[--b_idx])) 
		{
#ifdef DEBUG
            cmpcnt++;
#endif
            if (p_idx == 0) 
			{
               	pri->doe_ptr = &(buf[b_idx]) + plen;
				//pri->offset += (pri->doe_ptr - pri->data);
				if (ct->use_record)
					pri->prd = pri->doe_ptr + ct->record_oft;
				
				//printf("founded<%c:%c:%c  %d>.", ptrn[0], ptrn[1], ptrn[2], ct->pattern_size);
                return 1;
            }
        }

        skip_stride = skip[toupper((unsigned char) buf[b_idx])];
        shift_stride = shift[p_idx];
        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }
	
    return 0;
}
/****************************************************************
 *
 *  Function: mSearch(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
static int
msearch(char *buf, int blen, char *ptrn,
			int plen, int *skip, int *shift,
			m_priv_t	*pri, RULE_CONTENT_MATCH *ct)
{
    int b_idx	= plen;

#ifdef DEBUG
    int cmpcnt	= 0;
#endif

    if (plen == 0)
        return 1;

    while	(b_idx <= blen) {
        int p_idx = plen, skip_stride, shift_stride;

        while(buf[--b_idx] == ptrn[--p_idx]) {
#ifdef DEBUG
            cmpcnt++;
#endif
            if (b_idx < 0)
                return 0;

            if (p_idx == 0) {
                pri->doe_ptr = &(buf[b_idx]) + plen;
				//pri->offset += (pri->doe_ptr - pri->data);
				if (ct->use_record)
					pri->prd =  pri->doe_ptr + ct->record_oft;
				//print("founded<%c:%c:%c  %d>.", ptrn[0], ptrn[1], ptrn[2], ct->pattern_size);
                return 1;
            }
        }

        skip_stride = skip[(unsigned char) buf[b_idx]];
        shift_stride = shift[p_idx];
        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    return 0;
}

/* 
 * single search function. 
 *
 * data = ptr to buffer to search
 * dlen = distance to the back of the buffer being tested, validated 
 *        against offset + depth before function entry (not distance/within)
 * ct = pointer to pattern match data struct
 * nocase = 0 means case sensitve, 1 means case insensitive
 */       
static int
do_unisearch(char *data, int dlen,
			RULE_CONTENT_MATCH *ct,
			int nocase, void *private)
{
    /* 
     * in theory computeDepth doesn't need to be called because the 
     * depth + offset adjustments have been made by the calling function
     */
    int			depth		= dlen;
    char		*start_ptr	= data;
    char		*end_ptr	= data + dlen;
    char		*base_ptr	= start_ptr;
	m_priv_t	*pri		= private;
	int			delta;

    /* check to see if we've got a stateful start point */
    if (ct->use_doe && pri->doe_ptr) {
        base_ptr	= pri->doe_ptr;
        depth		= dlen - (pri->doe_ptr - data);
    } else {
        base_ptr	= start_ptr;
        depth		= dlen;
    }
	
    /* if we're using a distance call */
    if (ct->distance) {
        /* set the base pointer up for the distance */
        base_ptr	+= ct->distance;
        depth		-= ct->distance;
	 /* otherwise just use the offset (validated by calling function) */
    }
	
	if (ct->eoffset) {
		delta = (int)((u_int16_t)pri->dlen - ct->eoffset);
		if (delta > 0) {
			base_ptr	= pri->data + delta;
			depth		= ct->eoffset;
		}
	} else if (ct->offset > pri->offset) {
        base_ptr	+= (ct->offset - pri->offset);
        depth		-= (ct->offset - pri->offset);
    }
	
    /* make sure we and in range */
    if (!in_bounds(start_ptr, end_ptr, base_ptr)) {
		print("Not in bounds s:%p e:%p b:%p", start_ptr, end_ptr, base_ptr);
        return 0;
    }
	
    if (depth < 0) {
        print("returning because depth is negative (%d)", depth);
        return 0;        
    }
	
    if (depth > dlen)
        depth = dlen;
    if ((ct->depth > 0) && (depth > ct->depth))
        depth = ct->depth;

    /* make sure we and in range */
    if (!in_bounds(start_ptr, end_ptr, base_ptr + depth - 1)) {
		print("returning because base_ptr + depth - 1"
             " is out of bounds start_ptr: %p end: %p base: %p\n",
             start_ptr, end_ptr, base_ptr);
        return 0;
    }
	
	
    int ret = nocase ? msearch_ci(base_ptr, depth, 
                            ct->pattern_buf,
                            ct->pattern_size,
                            ct->skip_stride, 
                            ct->shift_stride, pri, ct)
                  : msearch(base_ptr, depth,
                          ct->pattern_buf,
                          ct->pattern_size,
                          ct->skip_stride,
                          ct->shift_stride, pri, ct);
	//printf("pattern_buf:%s depth:%d nocase:%d ret:%d \n", ct->pattern_buf,depth,nocase,ret);
	return ret == 0 ? RET_FAILED:RET_SUCCESS;
}

static int match_all_content(m_priv_t *priv,RULE_DETAIL_INFO *r)
{
	RULE_CONTENT_MATCH *ct = NULL;
	
	ct = r->ds_list[RESV_PATTERN_MATCH];
	//printf("Line = %d pat %s \n",__LINE__,ct->pattern_buf);

	/**
	 * @brief 
	 * 	到这里就表示已经acs匹配成功
	 * 	如果规则只有一个选项则无需继续
	 */
	if (!ct->next) {
		priv->prd = priv->data + priv->offset + ct->pattern_size;
		return RET_SUCCESS;
	}
	/**
	 * @brief 
	 * 	这里不应该是匹配ct->next?
	 */
	
	while(ct){
		//if(ct->search(priv->data + priv->offset,
		//		priv->dlen - priv->offset, ct, private)){
		//printf("Line = %d priv->offset %d pat %s \n",__LINE__,priv->offset,ct->pattern_buf);
		if(do_unisearch(priv->data + priv->offset,
				priv->dlen - priv->offset, ct, ct->nocase,priv) == RET_SUCCESS) 
		{
			
			/*越过同级别的或关系匹配字段*/
			while(ct->next && ((RULE_CONTENT_MATCH *)ct->next)->do_or)
			{
				ct = (RULE_CONTENT_MATCH *)ct->next;
			}
			ct = (RULE_CONTENT_MATCH *)ct->next;
		}
		else
		{
			
			/*如果没有匹配上,查看是否还有同一级别或关系匹配的字段*/
			if(ct->next && ((RULE_CONTENT_MATCH *)ct->next)->do_or)
			{
				ct = (RULE_CONTENT_MATCH *)ct->next;
			}
			else
			{
				goto out;
			}
		}	
	}
	return RET_SUCCESS;
out:
	return RET_FAILED;
}

static int acs_match_cb(void * id, void *tree, int index, void *data, void *neg_list)
{
	int ret = RET_FAILED;  //nofound
	pat_node_t	*pn				 	= id;
	RULE_DETAIL_INFO *pstRuleInfo   = pn->pstRuleDetail;
	m_priv_t		*priv 			= data;
	priv->offset 					= index;
	priv->pstRuleDetail             = pstRuleInfo;
	
	//printf("func %s line %d \n",__FUNCTION__,__LINE__);
	if(match_all_content(priv,pstRuleInfo) < 0)
		return ret;
	//printf("func %s line %d \n",__FUNCTION__,__LINE__);
	RULE_TARGET_INFO      *pstTagetInfo = &pstRuleInfo->stTargetInfo;
	const TARGET_TYPE_MAP *pstTargetMap = pstTagetInfo->pstTargetMap;
	const PROTOCOL_CONTORL_INFO *pstCtrlInfo = (const PROTOCOL_CONTORL_INFO *)pstTargetMap->extend;
	//printf("Now match one rule,action is %s ,need handle %s \n",pstTagetInfo->strName,pstCtrlInfo ? "Yes" : "No");
	NIDS_CONNTRACK_RECORD *pstConn = (NIDS_CONNTRACK_RECORD *)priv->pstconn;
	//may be need entern critical
	//printf("func %s line %d \n",__FUNCTION__,__LINE__);
	if(pstCtrlInfo && pstCtrlInfo->cbProtoHandle && (ret = pstCtrlInfo->cbProtoHandle(pstTagetInfo->eAction,priv)) == RET_SUCCESS) //need get clear type
	{
		pstConn->eMainType = pstTargetMap->eType;
		pstConn->eSubType  |= SET_STREAM_ACTION(_STREAM_GATHER_BASE);
		//printf("action is %s , %s handle success  \n",pstTagetInfo->strName,pstCtrlInfo->strName);
	}
	return ret == RET_SUCCESS ? 1 : -1;
}
static inline int
prepare_priv(m_priv_t *private, char *data, int dlen, void *r,struct ethhdr *pstEthInfo,struct tuple4 *addr,int direction)
{
	if (dlen <= 4)
		goto out;

	private->data				= data;
	private->dlen				= dlen;
	private->end				= data + dlen;
	private->offset				= 0;
	private->pstRuleDetail		= r;
	private->prd				= NULL;
	private->doe_ptr			= NULL;
	private->stEthInfo          = *pstEthInfo;
	private->ht          		= *addr;
	private->slDir          	= direction;
	return 0;
out:
	return -1;
	
}

static int do_acs_match(port_grp_t	*pstPortGroup,char *data, int dlen,void *private)
{
	int start_state = 0;
	if(!pstPortGroup->pat_match)
		return RET_FAILED;
	//printf("Line = %d \n",__LINE__);
	/*
	*	为了在acs匹配完之后继续匹配
	*	作为私有数据传递出原始数据
	*/	
	// m_priv_t private;
	// bzero(&private,sizeof(private));
	
	// if (prepare_priv(&private, data, dlen,NULL,pstEthInfo,addr))
	// 	return RET_FAILED;
		
	//printf("Line = %d dlen = %d \n",__LINE__,dlen);
	return acsmSearch2(pstPortGroup->pat_match, (unsigned char *)data,
							dlen, acs_match_cb,
							(void *)private, &start_state);
}


/**
 * @brief 
 * 	这里先采集基本信息,并且会标记流信息
 *  用于后面的扩展
 * @param data 
 * @param slDataLen 
 * @param slProtocol 
 * @param addr 
 * @param pstEthInfo 
 * @param direction 
 * @param pstConn 
 * @return int 
 */

static int do_gather_base(void *data,int slDataLen,int slProtocol,
	struct tuple4 *addr,struct ethhdr *pstEthInfo,int direction,NIDS_CONNTRACK_RECORD *pstConn)
{
	m_priv_t private;
	bzero(&private,sizeof(private));
	//printf("Func = %s,Line=%d \n",__FUNCTION__,__LINE__);
	/**
	 * @brief 
	 * 	已经确认是那种是目标的数据流
	 * 	
	 */
	if( CONN_MAIN_INVALID != pstConn->eMainType  ||
		CHECK_STREAM_ACTION(pstConn->eSubType,_STREAM_GATHER_BASE)
		)
	{
		printf("This stream base info is gathered,type is %d %d  \n",pstConn->eMainType,pstConn->eSubType);
		return RET_SUCCESS;
	}

	
	port_grp_t	*pstPortGroup = find_grp_skb(addr,slProtocol,direction);
	//printf("Func = %s,Line=%d \n",__FUNCTION__,__LINE__);
	if(pstPortGroup && pstPortGroup->nrule)
	{
		if (prepare_priv(&private, data, slDataLen,NULL,pstEthInfo,addr,direction))
			return RET_FAILED;

		private.pstconn = pstConn;
		printf("Line = %d rulNum = %d port %d\n",__LINE__,pstPortGroup->nrule,pstPortGroup->port);
		return do_acs_match(pstPortGroup,data,slDataLen,&private);
	}
	return RET_FAILED;
}
/**
 * @brief 
 * 	检查地址参数是否正确
 * 	比如广播地址不接受
 *  或许这里可以在nids中使用过滤条件
 * @param addr 
 * @return int 
 */
inline int do_check_tuple(struct tuple4 *addr)
{
	if(addr->saddr == 0 || addr->saddr == 0xffffffff ||
		addr->daddr == 0 || addr->daddr == 0xffffffff)
	{
		return RET_FAILED;
	}
	else
	{
		return RET_SUCCESS;
	}

}
/**
 * @brief 
 * 	完成數據的檢測工作
 *  包括數據的分析、存儲等
 * 	匹配流程
 * 	1.先通过端口信息过去port_group(find_grp_skb)
 * 	2.每个port_gourp上面注册一些content，即匹配规则(do_acs_match)
 *  3.当acs匹配上content之后,即可通过当前content获取出规则(acs_match_cb)
 *  4.获取出规则之后对规则的全部content匹配(match_all_content)
 *  5.如果匹配成功，则表示是当前对象的数据流，则进入对象的处理(pstCtrlInfo->cbProtoHandle(pstTagetInfo->eAction,priv)
 * @param tuple 
 * @param data 
 * @param slDataLen 
 * @param slProtocol 
 * @param ethInfo 
 * @return int 
 */
int snort_do_detect(void *tuple,void *data,int slDataLen,int slProtocol,void *ethInfo,void * conn)
{
	//int i = 0;
	struct tuple4 *addr       		= (struct tuple4 *)tuple;
	struct ethhdr *pstEthInfo 		= (struct ethhdr *)ethInfo;
	//unsigned char *stream 			= data;
	NIDS_CONNTRACK_RECORD *pstConn 	= (NIDS_CONNTRACK_RECORD *)conn;
	int direction 					= pstConn->eDir;

	if(do_check_tuple(addr) < 0)
	{
		return RET_FAILED;
	}
	/**
	 * @brief Construct a new do gather base object
	 * 	采集基本信息
	 */
	do_gather_base(data,slDataLen,slProtocol,addr,pstEthInfo,direction,pstConn);

	#ifndef TRAFFIC_CMCC
	/**
	 * @brief 
	 * 	do something else,such as analyse http log
	 */
	do_insight_http(data,slDataLen,slProtocol,addr,pstEthInfo,direction,pstConn);
	/**
	 * @brief 
	 * 	do something else,such as analyse email
	 */
	do_insight_email(data,slDataLen,slProtocol,addr,pstEthInfo,direction,pstConn);
	#endif
	
	return RET_SUCCESS;
}