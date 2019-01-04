/*
 * @Author: jiamu 
 * @Date: 2018-10-17 17:16:00 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:28:00
 */
#include "protocol.h"
#include "snort_content.h"
#include "snort_file.h"

#define TBKEY						"cntaobao" 
#define TB_UNICODE_CHAR			"%5Cu"

#define TBTM_KEY_WORD			"tmall_"
#define TBTM_AT1					"@"
#define TBTM_AT2					"%40"
#define TBTM_ADRD_KEY				"android_"
#define TBTM_IOS_KEY				"iphone_"

#define TAOBAO_ENTRY_NUM			(32)
#define TAOBAO_SIZE_MAX			(128)
#define TAOBAO_REAL_SIZE_MIN		(3)
#define TAOBAO_REAL_SIZE_MAX		(64)
#define TAOBAO_SND_CYCLE			(HZ << 5) /* 32s */
#define TAOBAO_BUF_SIZE			(TAOBAO_ENTRY_NUM * TAOBAO_SIZE_MAX)
#define TAOBAO_MIN_VALID_CHAR	0x30


static int do_taobao_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    if (priv->prd) {
        unsigned char buf[TAOBAO_REAL_SIZE_MAX] = {0};
        
		int			size = 0;
		int			wnum = 0;
		int			is_uni = 0;
		const char	*ptr;
		const char	*headptr = priv->prd;
		char			*tmptr = NULL;
       //RULE_DETAIL_INFO *r = (RULE_DETAIL_INFO *)(priv->pstRuleDetail);
#if 0
		print("patern:%s data:%s\n ht:%x %x %d %d len:%d"
			,((RULE_CONTENT_MATCH *)(r->ds_list[0]))->pattern_buf
			,priv->prd ? priv->prd : "NULL"
			,priv->ht.saddr, priv->ht.daddr
			,priv->ht.source, priv->ht.dest
			,priv->dlen);
#endif
		skip_space(priv->prd);
		ptr = priv->prd;

		if (((priv->end-ptr-1) > strlen(TBKEY))
			&& (strncmp((ptr+1), TBKEY, strlen(TBKEY)) == 0)) {
			// found hex type account
			wnum = (*ptr - strlen(TBKEY));
			if (wnum > 0 && wnum < TAOBAO_SIZE_MAX) {
				ptr += (strlen(TBKEY) + 1);
				headptr = ptr;
				while (size < wnum && *ptr != '@' && *ptr != ' ' && *ptr != ';' && *ptr != '&'
					&& *ptr != 0 && size < TAOBAO_SIZE_MAX && ptr < priv->end) {
					if (*ptr != '%' && ((*ptr & 0xFF) < TAOBAO_MIN_VALID_CHAR)) {
						break;
					}
					if (0 == strncmp(ptr, TB_UNICODE_CHAR, strlen(TB_UNICODE_CHAR))) {
						is_uni++;
					}
					ptr++, size++;
				}
			}
		} else {
			while (*ptr != '@' && *ptr != ' ' && *ptr != ';' && *ptr != '&'
				&& *ptr != 0 && size < TAOBAO_SIZE_MAX && ptr < priv->end) {
				if (*ptr != '%' && ((*ptr & 0xFF) < TAOBAO_MIN_VALID_CHAR)) {
					break;
				}
				if (0 == strncmp(ptr, TB_UNICODE_CHAR, strlen(TB_UNICODE_CHAR))) {
					is_uni++;
				}

				ptr++, size++;
			}
		}
		if (size && size < TAOBAO_SIZE_MAX && size > 3) {
			char uname[TAOBAO_REAL_SIZE_MAX+1];
			int uname_num = 0;

			if (!is_uni) {
				uname_num = ConvertUrlToAscii(uname, TAOBAO_REAL_SIZE_MAX, headptr, size);
				printpkt("uname_num=%d, uname [%s]", uname_num, uname);
			} else {
				uname_num = ConvertNativeToAscii(uname, TAOBAO_REAL_SIZE_MAX, headptr, size);
				printpkt("unicode uname_num=%d, uname [%s]", uname_num, uname);
			}

			if (uname_num > TAOBAO_REAL_SIZE_MIN && uname_num < TAOBAO_REAL_SIZE_MAX) {
				// check is tmall data
				// find string "%40tmall_iphone_","%40tmall_android_","@tmall_iphone_","@tmall_android_"
				tmptr = strnstr(priv->prd, TBTM_KEY_WORD, priv->end-priv->prd);
				if (tmptr) {
				do {
					if (strnstr(tmptr-strlen(TBTM_AT1), TBTM_AT1, strlen(TBTM_AT1))) {
						;
					} else if (strnstr(tmptr-strlen(TBTM_AT2), TBTM_AT2, strlen(TBTM_AT2))) {
						;
					} else {
						break;
					}

					if (strnstr(tmptr+strlen(TBTM_KEY_WORD), TBTM_ADRD_KEY, strlen(TBTM_ADRD_KEY))) {
						;
					} else if (strnstr(tmptr+strlen(TBTM_KEY_WORD), TBTM_IOS_KEY, strlen(TBTM_IOS_KEY))) {
						;
					} else {
						break;
					}
					printpkt("found tmall");
                    memcpy(buf,uname,uname_num);
                    printf("taobao-->size:%d info:%s \n",uname_num,uname);
					do_record_data(buf,uname_num,priv);
					// priv->ptl->msg.mc_add(priv->ptl, TMALL
					// 			, uname, uname_num, ip, mac);
					return RET_SUCCESS;
				} while (0);
				}
				memcpy(buf,uname,uname_num);
				do_record_data(buf,uname_num,priv);
                printf("taobao-->size:%d info:%s \n",uname_num,uname);

				// priv->ptl->msg.mc_add(priv->ptl, TAOBAO
				// 			, uname, uname_num, ip, mac);
				return RET_SUCCESS;
			}
		}
	}

	return RET_FAILED;
}
static int do_taobao_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO sttaobaoCtrlInfo = {
    .strName        = "TAOBAO",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_taobao_action,
    .cbProtoPack    = do_taobao_pack,
    .private        = NULL
};

