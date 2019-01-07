/*
 * @Author: jiamu 
 * @Date: 2018-09-29 17:37:22 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-07 17:02:27
 */

#include "snort_file.h"
#include "log.h"
#include "list.h"
#include <string.h>
#include "protocol.h"

#ifndef PARSERULE_SIZE
#define PARSERULE_SIZE	     2048
#endif

static int file_line = 0;

static RULE_DETAIL_INFO stTcpRuleInfp;
static RULE_DETAIL_INFO stUdpRuleInfp;
static RULE_DETAIL_INFO stIcmpRuleInfp;
static RULE_DETAIL_INFO stIpRuleInfp;

#define RULE_MODE_SRCIP		1
#define RULE_MODE_DSTIP		2
#define RULE_TARGET_STR		"target"
#define RULE_TARGET_SIZ		sizeof(RULE_TARGET_STR)

#define BROADCAST_ADDR_STR	"255.255.255.255"
#define BROADCAST_ADDR_LEN	(sizeof(BROADCAST_ADDR_STR) - 1)


extern PROTOCOL_CONTORL_INFO stQQCtrlInfo;
extern PROTOCOL_CONTORL_INFO stWECHATCtrlInfo;
extern PROTOCOL_CONTORL_INFO stVIPSHOPCtrlInfo;
extern PROTOCOL_CONTORL_INFO stALIWXCtrlInfo;
extern PROTOCOL_CONTORL_INFO stBDTBCtrlInfo;
extern PROTOCOL_CONTORL_INFO stDIANPINGCtrlInfo;
extern PROTOCOL_CONTORL_INFO stdidiCtrlInfo;
extern PROTOCOL_CONTORL_INFO stFEIXINCtrlInfo ;
extern PROTOCOL_CONTORL_INFO stGANJICtrlInfo;
extern PROTOCOL_CONTORL_INFO stJDCtrlInfo ;
extern PROTOCOL_CONTORL_INFO sttaobaoCtrlInfo;
extern PROTOCOL_CONTORL_INFO stMEITUANCtrlInfo;
extern PROTOCOL_CONTORL_INFO stKUAIDICtrlInfo;
extern PROTOCOL_CONTORL_INFO stM139CtrlInfo;
extern PROTOCOL_CONTORL_INFO stM189CtrlInfo;
extern PROTOCOL_CONTORL_INFO stMILIAOCtrlInfo;
extern PROTOCOL_CONTORL_INFO stMOMOCtrlInfo ;
extern PROTOCOL_CONTORL_INFO stMPLTCtrlInfo;
extern PROTOCOL_CONTORL_INFO stMQQCtrlInfo ;
extern PROTOCOL_CONTORL_INFO stMSINACtrlInfo;
extern PROTOCOL_CONTORL_INFO stQQMCtrlInfo;
extern PROTOCOL_CONTORL_INFO stQUNARCtrlInfo;
extern PROTOCOL_CONTORL_INFO stRJCtrlInfo;
extern PROTOCOL_CONTORL_INFO stTC58CtrlInfo;
extern PROTOCOL_CONTORL_INFO stTMALLCtrlInfo;
extern PROTOCOL_CONTORL_INFO stTXWBCtrlInfo;
extern PROTOCOL_CONTORL_INFO stTYCtrlInfo;
extern PROTOCOL_CONTORL_INFO stWY163CtrlInfo;
extern PROTOCOL_CONTORL_INFO stXCCtrlInfo ;
extern PROTOCOL_CONTORL_INFO stXLWBCtrlInfo;
extern PROTOCOL_CONTORL_INFO stYLCtrlInfo;
extern PROTOCOL_CONTORL_INFO stHttpCtrlInfo;
extern PROTOCOL_CONTORL_INFO stSMTPCtrlInfo;
extern PROTOCOL_CONTORL_INFO stIMAP4CtrlInfo;
extern PROTOCOL_CONTORL_INFO stPOPCtrlInfo;
extern PROTOCOL_CONTORL_INFO stMALACtrlInfo;
extern PROTOCOL_CONTORL_INFO stBAOFENGCtrlInfo;
extern PROTOCOL_CONTORL_INFO stFEIZHUCtrlInfo ;
extern PROTOCOL_CONTORL_INFO stDOUYUCtrlInfo;
extern PROTOCOL_CONTORL_INFO stYOUKUCtrlInfo ;
extern PROTOCOL_CONTORL_INFO stMEIPAICtrlInfo;

CHECK_RULE_INFO  stCheckRuleInfo[]=
{
    {"TCP",&stTcpRuleInfp},
    {"UDP",&stUdpRuleInfp},
    {"ICMP",&stIcmpRuleInfp},
    {"IP",&stIpRuleInfp},
};

static RULE_TARGET_INFO const stTargetMap[] =
{
    {"RECORD" ,_ACTION_RECORD},
    {"setmark",_ACTION_MARK},
    {"DROP"   , _ACTION_DROP},
};
static TARGET_TYPE_MAP const stTargetTypeMap[] = 
{
    {"QQ",_TARGET_QQ,&stQQCtrlInfo},
    {"MQQ",_TARGET_MQQ,&stMQQCtrlInfo},
    {"WCHAT",_TARGET_WCHAT,&stWECHATCtrlInfo},
    {"ALIWX",_TARGET_ALIWX,&stALIWXCtrlInfo},
    {"MILIAO",_TARGET_MILIAO,&stMILIAOCtrlInfo},
    {"WY163",_TARGET_WY163,&stWY163CtrlInfo},
    {"QQM",_TARGET_QQM,&stQQMCtrlInfo},
    {"M189",_TARGET_M189,&stM189CtrlInfo},
    {"M139",_TARGET_M139,&stM139CtrlInfo},
    {"MSINA",_TARGET_MSINA,&stMSINACtrlInfo},

    {"TY",_TARGET_TY,&stTYCtrlInfo},
    {"BDTB",_TARGET_BDTB,&stBDTBCtrlInfo},
    {"MPLT",_TARGET_MPLT,&stMPLTCtrlInfo},
    {"TXWB",_TARGET_TXWB,&stTXWBCtrlInfo},
    {"XLWB",_TARGET_XLWB,&stXLWBCtrlInfo},
    {"TAOBAO",_TARGET_TAOBAO,&sttaobaoCtrlInfo},
    {"TMALL",_TARGET_TMALL,&stTMALLCtrlInfo},
    {"JD",_TARGET_JD,&stJDCtrlInfo},
    {"XC",_TARGET_XC,&stXCCtrlInfo},
    {"QUNAR",_TARGET_QUNAR,&stQUNARCtrlInfo},
    {"YL",_TARGET_YL,&stYLCtrlInfo},

    {"M126",_TARGET_M126,NULL},
    {"FEIXIN",_TARGET_FEIXIN,&stFEIXINCtrlInfo},
    {"MOMO",_TARGET_MOMO,&stMOMOCtrlInfo},
    {"VIPSHOP",_TARGET_VIPSHOP,&stVIPSHOPCtrlInfo},
    {"MEITUAN",_TARGET_MEITUAN,&stMEITUANCtrlInfo},
    {"DIANPING",_TARGET_DIANPING,&stDIANPINGCtrlInfo},
    {"DIDI",_TARGET_DIDI,&stdidiCtrlInfo},
    {"KUAIDI",_TARGET_KUAIDI,&stKUAIDICtrlInfo},
    {"TC58",_TARGET_TC58,&stTC58CtrlInfo},
    {"GANJI",_TARGET_GANJI,&stGANJICtrlInfo},
    {"HTTP",_TARGET_HTTP,&stHttpCtrlInfo},   
    {"SMTP",_TARGET_SMTP,&stSMTPCtrlInfo},  
    {"IMAP4",_TARGET_IMAP4,&stIMAP4CtrlInfo},   
    {"POP3",_TARGET_POP3,&stPOPCtrlInfo},   
    {"MALASHEQU",_TARGET_MALASHEQU,&stMALACtrlInfo},
    {"BAOFENG",_TARGET_BAOFENG,&stBAOFENGCtrlInfo},
    {"FEIZHU",_TARGET_FEIZHU,&stFEIZHUCtrlInfo},
    {"DOUYU",_TARGET_DOUYU,&stDOUYUCtrlInfo},
    {"YOUKU",_TARGET_YOUKU,&stYOUKUCtrlInfo},
    {"MEIPAI",_TARGET_MEIPAI,&stMEIPAICtrlInfo},
};

#define malloc_assert(type, size) ({\
	type _tmp = (type)calloc(1, size);\
\
	if (!_tmp)\
		fatal("malloc failed.");\
	_tmp;\
})

/* 
 * current line being processed in the rules file
 */

#define netmask(bits) ({\
	int _i;\
	u_int32_t msk = 0;\
\
	for (_i = 0; _i < bits; _i++)\
		msk |= (1 << (31 - _i));\
	htonl(msk);\
})

#define port_trans(p) ({\
	u_int32_t _pt = 0;\
\
	if (!is_all_digit(p))\
		fatal("%s(%d) => Bad port number: \"%s\"\n", \
               file, file_line, p);\
	_pt = strtoul(p, NULL, 10);\
\
    if ((_pt == 0) || (_pt > USHRT_MAX))\
		fatal("%s(%d) => bad port number: %s\n", file, file_line, p);\
	(_pt);\
})

#define casehelper(p, e, m, v) ({\
	switch(m) {\
	case RULE_MODE_SRCIP:\
		p->e##_s = v;\
		break;\
	case RULE_MODE_DSTIP:\
		p->e##_d = v;\
		break;\
	}\
})


#define ifhelper(r, p1, p2) ({\
	if (!strcasecmp(p1, #p2)) {\
        r->proto = IPPROTO_##p2;\
        goto out;\
    }\
})

int parse_rules_file(const char *file, int inclevel);

static inline int
check_linebreak(char *rule)
{
    char *idx = rule + strlen(rule) - 1;
	int ret = 0;

    while(isspace((int)*idx))
		idx--;

    if (*idx == '\\') {
        print("Got continuation char, clearing char and returning 1");
        /*
         * clear the '\' so there isn't a problem on the appended string
         */
        *idx = 0;
        ret = 1;
    }

    return ret;
}


static inline int
strip(char *data)
{
    size_t size = strlen(data);

    while (*data) {
		/*
		 * remove character at end.
		 */
        if ((*data == '\n') || (*data == '\r')) {
            *data = 0;
            size--;
        }
		data++;
    }
    return size;
}


static char **
msplit(char *str, const char *sep, int max_strs, int *toks, char meta)
{
    char **retstr;      /* 2D array which is returned to caller */
    char *idx;          /* index pointer into str */
    char *end;          /* ptr to end of str */
    const char *sep_end;      /* ptr to end of seperator string */
    const char *sep_idx;      /* index ptr into seperator string */
    int len = 0;        /* length of current token string */
    int curr_str = 0;       /* current index into the 2D return array */
    char last_char = (char) 0xFF;

    if (!toks) {
		fatal("bad toks.");
		goto bad;
	}

    *toks = 0;
    if (!str) {
		fatal("bad str.");
		goto bad;
	}

    /*
     * find the ends of the respective passed strings so our while() loops
     * know where to stop
     */
    sep_end = sep + strlen(sep);
    end = str + strlen(str);

    /*
     * remove whitespace 
     */
#if 0
    while (isspace((int) *(end - 1)) && ((end - 1) >= str))
        *(--end) = '\0';
#endif
    sep_idx = sep;
    idx = str;
	retstr = malloc_assert(char **, (sizeof(char **) * max_strs));

    while (idx < end) {
        while (sep_idx < sep_end) {
            if ((*idx == *sep_idx) && (last_char != meta)) {
                if (len > 0) {
                    if (curr_str < max_strs) {
                        retstr[curr_str] = malloc_assert(char *,(len + 1));
                        memcpy(retstr[curr_str], (idx - len), len);
                        print_dbg("tok[%d]: %s\n", curr_str, retstr[curr_str]);
                        len = 0;
                        curr_str++;
                    }
                    if (curr_str >= max_strs)
						goto out;
                }
				goto update;
            } else
                sep_idx++;
        }
		len++;
update:
        sep_idx = sep;        
        last_char = *idx;
        idx++;
    }

	/*
	 * deal with last characters.
	 */
	if (len) {
		retstr[curr_str] = malloc_assert(char *,(len + 1));
        memcpy(retstr[curr_str], (idx - len), len);
        print_dbg("tok[%d]: %s\n", curr_str, retstr[curr_str]);
		curr_str++;
	}
out:
	*toks = curr_str;
    return retstr;
bad:
	return NULL;
}


static void
msplit_free(char ***pbuf, int num_toks)
{
    int i;
    char** buf;  /* array of string pointers */

    if (pbuf == NULL || *pbuf == NULL )
        return;

    buf = *pbuf;

    for ( i = 0; i < num_toks; i++ )
        if ( buf[i] != NULL )
            free( buf[i] );

    free(buf);
    *pbuf = NULL;
}


static inline int
process_proto(char **proto,  RULE_HEAD_INFO *pstHeadInfo, char *file)
{
	char *proto_str = proto[0];

	ifhelper(pstHeadInfo, proto_str, TCP);
	ifhelper(pstHeadInfo, proto_str, UDP);
	ifhelper(pstHeadInfo, proto_str, ICMP);
	ifhelper(pstHeadInfo, proto_str, IP);

    /*
     * if we've gotten here, we have a protocol string we din't recognize and
     * should exit
     */
    fatal("%s(%d) => Bad protocol: %s\n", file, file_line, proto_str);
out:
    return 0;
}


static int
parse_ip(char *paddr, NET_TUPLE_SET *ipset, char *file)
{
    char **toks;        /* token dbl buffer */
    int num_toks;       /* number of tokens found by mSplit() */
    int cidr = 1;       /* is network expressed in CIDR format */
    int nmask;          /* netmask temporary storage */
    char *addr;         /* string to parse, eventually a variable-contents */

    addr = paddr;
    /*
     * break out the CIDR notation from the IP address
     */
    toks = msplit(addr, "/", 2, &num_toks, 0);
    /*
     * "/" was not used as a delimeter, try ":"
     */
    if (num_toks == 1) {
        msplit_free(&toks, num_toks);
        toks = msplit(addr, ":", 2, &num_toks, 0);
    }

    /*
     * if we have a mask spec and it is more than two characters long, assume
     * it is netmask format
     */
    if ((num_toks > 1) && strlen(toks[1]) > 2)
        cidr = 0;

    switch (num_toks) {
    case 1:
        ipset->ulNetMask = netmask(32);
        break;
    case 2:
        if (cidr) {
			if (!is_all_digit(toks[1]))
				fatal("ERROR %s(%d): Invalid CIDR netmask for IP addr "
					"%s\n", file, file_line, addr);
            /*
             * convert the CIDR notation into a real live netmask
             */
            nmask = strtoul(toks[1], NULL, 10);

            if ((nmask > -1) && (nmask < 33))
				ipset->ulNetMask = netmask(nmask);
            else
                fatal("ERROR %s(%d): Invalid CIDR block for IP addr "
                        "%s\n", file, file_line, addr);
        } else {
            /* convert the netmask into its 32-bit value */
			if (!strncmp(toks[1], BROADCAST_ADDR_STR, BROADCAST_ADDR_LEN))
                ipset->ulNetMask = netmask(32);
			else if (inet_pton(AF_INET, toks[1], &ipset->ulNetMask) != 1)
                fatal("ERROR %s(%d): Unable to parse rule netmask "
                        "(%s)\n", file, file_line, toks[1]);
        }
        break;
    default:
        fatal("ERROR %s(%d) => Unrecognized IP address/netmask %s\n",
                file, file_line, addr);
        break;
    }

	if (isalpha((int) toks[0][0]))
        fatal("ERROR %s(%d) => Don Not support names %s\n",
			file, file_line, addr);
    if (!strncmp(toks[0], BROADCAST_ADDR_STR, BROADCAST_ADDR_LEN))
        ipset->ulIpAddr = netmask(32);
    else if ((nmask = inet_pton(AF_INET, toks[0], &ipset->ulIpAddr)) != 1)
		fatal("ERROR %s(%d): Rule IP addr (%s) translate failed.<errno:%s ret:%d>", 
                file, file_line, toks[0], strerror(errno), nmask);
    msplit_free(&toks, num_toks);

    return 0;
}                                                                                            


static int
process_ip(char **addr,  RULE_HEAD_INFO *pstHeadInfo, int mode, char *file)
{
	NET_TUPLE_SET *pstIp = mode == RULE_MODE_DSTIP ?  &pstHeadInfo->stDstInfo : &pstHeadInfo->stSrcInfo;
	int skip_toks = 0;
	char *ipstr = addr[skip_toks];

	/* check for wildcards */
    if (!strcasecmp(ipstr, "any")) {
		casehelper(pstHeadInfo, any_ip, mode, 1);
		goto out;
    }

    if (*ipstr == '!') {
		casehelper(pstHeadInfo, n_ip, mode, 1);

		if (strlen(ipstr) > 1)
        	ipstr++;
		else
			ipstr = addr[++skip_toks];
    }

	//bzero(&ip, sizeof(ip));
	parse_ip(ipstr, pstIp, file);
	//casehelper(pstHeadInfo, ip, mode, ip);
out:
    return skip_toks;
}


static int
parse_port(char *port_str, NET_TUPLE_SET *port,
		 RULE_HEAD_INFO *pstHeadInfo, int mode, char *file)
{
	char **toks;        /* token dbl buffer */
    int num_toks;       /* number of tokens found by msplit() */
	char *ps,*pe;

	toks = msplit(port_str, ":", 2, &num_toks, 0);
	ps = toks[0],pe = toks[1];
	
	switch (num_toks) {
    case 1:
		if (port_str[0] == ':') {
			port->usLow = 0;
			port->usHigh = (u_int16_t)port_trans(ps);
			casehelper(pstHeadInfo, any_port, mode, 1);
		} else if (port_str[strlen(port_str) - 1] == ':') {
			port->usLow = (u_int16_t)port_trans(ps);
			port->usHigh= USHRT_MAX;
			casehelper(pstHeadInfo, any_port, mode, 1);
		} else
			port->usHigh = port->usLow = (u_int16_t)port_trans(ps);
        break;
    case 2:
		port->usLow = (u_int16_t)port_trans(ps);
		port->usHigh = (u_int16_t)port_trans(pe);
		casehelper(pstHeadInfo, any_port, mode, 1);
		break;
    default:
        fatal("%s(%d) => port conversion failed on \"%s\"\n",
                   file, file_line, port_str);
    }

    msplit_free(&toks, num_toks);
	return 0;
}


static int
process_port(char **port,  RULE_HEAD_INFO *pstHeadInfo, int mode, char *file)
{
	int skip_toks = 0;
	char *port_str = port[skip_toks];

	/*
     * check for wildcards
     */
    if (!strcasecmp(port_str, "any")) {
		casehelper(pstHeadInfo, any_port, mode, 1);
        goto out;
    }

	if (*port_str == '!') {
		casehelper(pstHeadInfo, n_port, mode, 1);

        if (strlen(port_str) > 1)
        	port_str++;
		else
			port_str = port[++skip_toks];
    }

	parse_port(port_str,mode == RULE_MODE_DSTIP ? &pstHeadInfo->stDstInfo : &pstHeadInfo->stSrcInfo, pstHeadInfo, mode, file);
out:
    return skip_toks;
}


static int
process_datalen(char **lenstr,  RULE_HEAD_INFO *pstHeadInfo, char *file)
{
	int skip_toks = 0, len;
	char *len_str = lenstr[skip_toks];
	char *lenl,*lenh;
	size_t ls =  0;

	if (strlen(len_str) < sizeof("datalen:"))
		goto out;

    if (strncasecmp(len_str, "datalen:", sizeof("datalen:") - 1))
        goto out;

	lenl = len_str + sizeof("datalen:") - 1;
	if ((lenh = strchr(lenl, ':'))) {
		*lenh = 0;
		lenh++;
	} else
		fatal("ERROR %s(%d): Bad data len format %s"
			" (shoule be <datalen:?:?>)."
				, file, file_line, len_str);

	ls = strlen(lenl);
	if (ls) {
		if (!is_all_digit(lenl))
			fatal("ERROR %s(%d): Invalid data len start[%s]."
					, file, file_line, len_str);
		len = atoi(lenl);
		if (len > USHRT_MAX)
			fatal("Bad data len %d (should < %d)", len, USHRT_MAX);
		pstHeadInfo->dlenh = pstHeadInfo->dlenl = (u_int16_t)len;
	} else
		pstHeadInfo->dlenl = 0;

	ls = strlen(lenh);
	if (ls) {
		if (!is_all_digit(lenh))
			fatal("ERROR %s(%d): Invalid data len end[%s]."
					, file, file_line, lenh);
		len = atoi(lenh);
		if (len > USHRT_MAX)
			fatal("Bad data len %d (should < %d)", len, USHRT_MAX);
		pstHeadInfo->dlenh = (u_int16_t)len;
	} else
		pstHeadInfo->dlenh = USHRT_MAX;

	if (pstHeadInfo->dlenh <= pstHeadInfo->dlenl)
		fatal("Bad range %d:%d", pstHeadInfo->dlenl, pstHeadInfo->dlenh);
out:
    return skip_toks;
}


static inline int
process_dir(char **dir,  RULE_HEAD_INFO *pstHeadInfo, char *file)
{
	char *dir_str = dir[0];
	int not_bdir = strcasecmp(dir_str, "<>"); 

	if (strcasecmp(dir_str, "->") && not_bdir)
		fatal("%s:%d => Port value missing in rule!", 
                   file, file_line);
	pstHeadInfo->b_bdir = !not_bdir;

	return 0;
}

/**
 * @brief 
 *  
 * @param toks 
 * @param num_toks 
 * @param pstRuleHeadInfo 
 * @param file 
 */
static void
parse_hdr(char **toks, int num_toks, RULE_HEAD_INFO* pstRuleHeadInfo, char *file)
{
#define check(n,s) {--n; n -= s; if (n < 1) fatal("%s(%d) =>n:%d Bad header.", file, file_line, n);}
	int skip_toks, toks_idx = 0;

	skip_toks = process_proto(&toks[toks_idx++], pstRuleHeadInfo, file);

	toks_idx += skip_toks;
	check(num_toks, skip_toks);
	skip_toks = process_ip(&toks[toks_idx++], pstRuleHeadInfo, RULE_MODE_SRCIP, file);

	toks_idx += skip_toks;
	check(num_toks, skip_toks);
	skip_toks = process_port(&toks[toks_idx++], pstRuleHeadInfo, RULE_MODE_SRCIP, file);

	toks_idx += skip_toks;
	check(num_toks, skip_toks);
	skip_toks = process_dir(&toks[toks_idx++], pstRuleHeadInfo, file);

	toks_idx += skip_toks;
	check(num_toks, skip_toks);
	skip_toks = process_ip(&toks[toks_idx++], pstRuleHeadInfo, RULE_MODE_DSTIP, file);

	toks_idx += skip_toks;
	check(num_toks, skip_toks);
	skip_toks = process_port(&toks[toks_idx++], pstRuleHeadInfo, RULE_MODE_DSTIP, file);

	toks_idx += skip_toks;
	check(num_toks, skip_toks);
	skip_toks = process_datalen(&toks[toks_idx++], pstRuleHeadInfo, file);
}


static char *
parse_opt(char *rule,  RULE_DETAIL_INFO *pstRuleInfo, char *file)
{
	char **toks, **opts;
    char *idx, *aux, *target = NULL;
    int num_toks, num_opts, i = 0;

	if (!(idx = index(rule, '(')))
		goto out;
	idx++;

	if (!(aux = rindex(rule, ')')))
		fatal("%s(%d): Missing trailing ')' in rule: %s.\n",
                       file, file_line, rule);
	*aux = 0;
	target = aux + 1;
	toks = msplit(idx, ";", 64, &num_toks, '\\');

	while (i < num_toks) {
		char* option_name;
		char* option_args;
        RULE_OPTION_INFO *pstNewOption = malloc_assert(RULE_OPTION_INFO *,sizeof(RULE_OPTION_INFO));
        memset(pstNewOption,0,sizeof(RULE_OPTION_INFO));
        init_list_head(&pstNewOption->list);

		opts = msplit(toks[i++], ":", 4, &num_opts, '\\');
		option_name = opts[0];
		option_args = opts[1];

        skip_space(option_name);
        //printf("option_name = %s option_args = %s \n ",option_name,option_args);
        strncpy(pstNewOption->strOptName,option_name,sizeof(pstNewOption->strOptName));
        if(option_args)
        {
            strncpy(pstNewOption->strOptVal,option_args,sizeof(pstNewOption->strOptVal));
        }
        //printf("option_name = %s option_args = %s %d \n ",pstNewOption->strOptName,pstNewOption->strOptVal,sizeof(RULE_OPTION_INFO));
        list_insert_tail(&pstNewOption->list,&pstRuleInfo->listOption);

		//do_resv(option_name, option_args, r, file);
		msplit_free(&opts, num_opts);
	}

	msplit_free(&toks, num_toks);
out:
	return target;
}

/*
 * At this moment options were parsed, so just search
 * 'target' as the begin of TARGET. Is this right???
 */
static int
parse_target(char *rule, RULE_DETAIL_INFO *pstRuleInfo, char *file)
{
	char **toks;
	int num_toks;
	char *tgt = strcasestr(rule, RULE_TARGET_STR);

    //printf("Rule:%s \n",rule);
	if (!tgt)
		fatal("%s(%d) => target is missing.", file, file_line);

	tgt += RULE_TARGET_SIZ;
	skip_space(tgt);
	toks = msplit(tgt, " ", 3, &num_toks, 0);
	if (num_toks < 1)
		fatal("%s(%d) => target is missing.", file, file_line);

	//do_target(toks[0], toks[1], r, file);
    //record
    int i = 0;
    pstRuleInfo->ruleNum = RULE_NUM_INVALID;
    RULE_TARGET_INFO *pstTargetInfo = &pstRuleInfo->stTargetInfo;

    //printf("action:%s type:%s \n",toks[0],toks[1]);
    for(i = 0;i < (sizeof(stTargetMap) / sizeof(stTargetMap[0]));i++)
    {
        if(strcasecmp(toks[0],stTargetMap[i].strName) == 0)
        {
            strcpy(pstTargetInfo->strName,stTargetMap[i].strName);
            pstTargetInfo->eAction = stTargetMap[i].eAction;
            break;
        }
    }
 
    if(i == (sizeof(stTargetMap) / sizeof(stTargetMap[0])))
    {
        fatal("%s(%s) => target is unknown.", file, toks[0]);
    }

    for(i = 0;i < (sizeof(stTargetTypeMap) / sizeof(stTargetTypeMap[0]));i++)
    {
        if(strcasecmp(toks[1],stTargetTypeMap[i].strName) == 0)
        {
            //pstTargetInfo->eType = stTargetTypeMap[i].eType;
            pstTargetInfo->pstTargetMap = &stTargetTypeMap[i];
            break;
        }
    }
  
    if(i == (sizeof(stTargetTypeMap) / sizeof(stTargetTypeMap[0])))
    {
        fatal("%s(%s) => target is unknown.", file, toks[1]);
    }
   
    if(num_toks == 3)
    {
        pstRuleInfo->ruleNum = atoi(toks[2]);
        printf("Now get rule handle num name is %s num is %d \n",toks[1],pstRuleInfo->ruleNum);
    }
	msplit_free(&toks, num_toks);

	return 0;
}

static inline int add_rule_list(RULE_DETAIL_INFO *pstRuleInfo)
{
    RULE_DETAIL_INFO *pstListHead = NULL;
    switch(pstRuleInfo->stRuleHeadInfo.proto)
    {
        case IPPROTO_TCP:
            pstListHead = &stTcpRuleInfp;
        break;
        case IPPROTO_UDP:
            pstListHead = &stUdpRuleInfp;
        break;
        case IPPROTO_IP:
            pstListHead = &stIpRuleInfp;
        break;
        case IPPROTO_ICMP:
            pstListHead = &stIcmpRuleInfp;
        break;
        default:
            fatal("Bad proto type %d.",pstRuleInfo->stRuleHeadInfo.proto);
        break;
    }
    list_insert_tail(&pstRuleInfo->listRule,&pstListHead->listRule);

    return RET_SUCCESS;
}

static void parse_rule(char *file, char *rule, int inclevel)
{
    char **toks;        /* dbl ptr for msplit call, holds rule tokens */
    int num_toks;       /* holds number of tokens found by msplit */
    char *tgt;
    RULE_DETAIL_INFO *pstSingleRule = NULL;

    
    /*
     * chop off the <CR/LF> from the string
     */
    strip(rule);
    
    /* 
     * break out the tokens from the rule string
     */
    toks = msplit(rule, " ", 11, &num_toks, 0);
   
	if (!strcasecmp(toks[0], "include")) {
		parse_rules_file(toks[1], inclevel + 1);
		msplit_free(&toks, num_toks);
        return;
	}

	pstSingleRule = malloc_assert(RULE_DETAIL_INFO *, sizeof(RULE_DETAIL_INFO));
    init_list_head(&pstSingleRule->listRule);
    init_list_head(&pstSingleRule->listOption);
	/*
	 * parse rule header.
	 */
	parse_hdr(toks, num_toks, &pstSingleRule->stRuleHeadInfo, file);
   
	msplit_free(&toks, num_toks);
   
	if ((tgt = parse_opt(rule, pstSingleRule, file)))
    {
        parse_target(tgt, pstSingleRule, file);
    }
	else
    {
        parse_target(rule, pstSingleRule, file);
    }
	add_rule_list(pstSingleRule);
}

/****************************************************************************
 *
 * Function: ParseRulesFile(char *, int)
 *
 * Purpose:  Read the rules file a line at a time and send each rule to
 *           the rule parser
 *
 * Arguments: file => rules file filename
 *            inclevel => nr of stacked "include"s
 *
 * Returns: 
 *  
 ***************************************************************************/
int parse_rules_file(const char *file, int inclevel)
{
    FILE *thefp;        /* file pointer for the rules file */
    char buf[STD_BUF] = {0};      /* file read buffer */
    char *index;        /* buffer indexing pointer */
    int stored_file_line;
    char *saved_line = NULL;
    int continuation = 0;
    char *new_line = NULL;
    struct stat file_stat; /* for include path testing */
    char strFileName[256] = {0};
    strncpy(strFileName,file,sizeof(strFileName));

    if(access(file,R_OK) != 0)
    {
        printf("%s is not exist or no read permission",strFileName);
        /*No rule file*/
        return RET_FILEERR;
    }

    if (inclevel == 0) 
    {
	    print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++");
	    print("Initializing rule chains...\n");
    }

    
    stored_file_line = file_line;
    file_line = 0;

    if (stat(strFileName, &file_stat) < 0) 
		fatal("ParseRulesFile: stat on %s failed.", strFileName);

    if((thefp = fopen(strFileName, "r")) == NULL)
        fatal("Unable to open rules file: %s or %s", strFileName, strFileName);

    while((fgets(buf, STD_BUF, thefp)) != NULL) {
        file_line++;
        index = buf;
       
		print_dbg("Got line %s (%d): %s", strFileName, file_line, buf);
        skip_space(index);
		print_dbg("%d", *index);
        /* if it's not a comment or a <CR>, send it to the parser */
        if (*index != '#' && *index != '\r' && *index != ';' && 
              *index != ' ' && *index != 0 && *index != '\n') {
            if (continuation == 1) {
				size_t olds = strlen(saved_line);
				size_t news = strlen(index);

                new_line = (char *)calloc(sizeof(char), olds + news + 1);
				if (new_line == NULL)
					fatal("calloc failed.");
                strncat(new_line, saved_line, olds);
                strncat(new_line, index, news);
                free(saved_line);
                saved_line = NULL;
                index = new_line;

                if (strlen(index) > PARSERULE_SIZE)
                    fatal("Please don't try to overflow the parser, "
                            "that's not very nice of you... (%d-byte "
                            "limit on rule size)\n", PARSERULE_SIZE);
                print("concat rule: %s\n", new_line);
            }
            if (check_linebreak(index)) {
				saved_line = strdup(index);
                continuation = 1;
            } else {
             	print_dbg("[*] Processing rule: %s\n", index);
                parse_rule(strFileName, index, inclevel);

                if (new_line != NULL) {
                    free(new_line);
                    new_line = NULL;
                    continuation = 0;
                }
            }   
        }
       
        bzero((char *) buf, STD_BUF);
    }

    file_line = stored_file_line;

    printf("Init ok inclevel = %d +++++++++++++++ \n",inclevel);
    if(inclevel == 0)
    {
        print("\n +++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");
    }
		
	if (thefp)
    	fclose(thefp);

    return RET_SUCCESS;
}
/**
 * @brief 
 *  change RULE_OPTION_INFO to RULE_CONTENT_MATCH
 *  and debug info    
 * output all rule list info to terminal
 */
static void snort_check_rules(void)
{
    RULE_DETAIL_INFO *pstRuleTmp   = NULL;

    RULE_OPTION_INFO *pstOptionTmp = NULL;
    RULE_OPTION_INFO *pstOptionPos = NULL;

    //struct list_head *pstListHead  = &stIcmpRuleInfp.listRule;
    int i = 0,j = 0;
    for(i = 0;i < (sizeof(stCheckRuleInfo) / sizeof(stCheckRuleInfo[0]));i++)
    {
        j = 0;
        printf("********************Now show %s rule info**************************\n",stCheckRuleInfo[i].strRuleInfo);
        list_for_each_entry(pstRuleTmp,&stCheckRuleInfo[i].pstRuleHead->listRule,listRule)
        {
            list_for_each_entry_safe(pstOptionTmp,pstOptionPos,&pstRuleTmp->listOption,list)
            {
                /*pstOptionTmp should be free*/
                rule_content_make(pstOptionTmp->strOptName,pstOptionTmp->strOptVal,pstRuleTmp,NULL);

                list_del(&pstOptionTmp->list);
                free(pstOptionTmp);
            }

            printf("Index:%*d    Target:%-16s   Action:%d   Name:%-16s     SrcIp:%08x SrcPort:%d DstIp:%08x DstPort:%d \n",5,j++,
            pstRuleTmp->stTargetInfo.strName,pstRuleTmp->stTargetInfo.eAction, pstRuleTmp->stTargetInfo.pstTargetMap->strName,
            pstRuleTmp->stRuleHeadInfo.stSrcInfo.ulIpAddr,htons(pstRuleTmp->stRuleHeadInfo.stSrcInfo.usLow),
            pstRuleTmp->stRuleHeadInfo.stDstInfo.ulIpAddr,htons(pstRuleTmp->stRuleHeadInfo.stDstInfo.usLow)); 

            rule_content_stride_make(pstRuleTmp);
        }
        printf("There are %d rules \n",j);
    }
}

int snort_init_file(const char *file)
{
    int i = 0;
    for(i = 0;i < (sizeof(stCheckRuleInfo)/ sizeof(stCheckRuleInfo[0]));i++)
    {
        memset(stCheckRuleInfo[i].pstRuleHead,0,sizeof(RULE_DETAIL_INFO));
        init_list_head(&stCheckRuleInfo[i].pstRuleHead->listOption);
        init_list_head(&stCheckRuleInfo[i].pstRuleHead->listRule);
    }
    
    parse_rules_file(file,0);

    snort_check_rules();

    snort_make_match(stCheckRuleInfo,sizeof(stCheckRuleInfo) / sizeof(stCheckRuleInfo[0]));
    return RET_SUCCESS;
}