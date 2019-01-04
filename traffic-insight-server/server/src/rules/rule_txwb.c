/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:30:31
 */

#include "protocol.h"

#define TXWB_ENTRY_NUM	(8)
#define TXWB_SIZE_MIN	(5)
#define TXWB_SIZE_MAX	(16)
#define TXWB_SND_CYCLE	(HZ << 5) /* 32s */
#define TXWB_BUF_SIZE	(TXWB_ENTRY_NUM * TXWB_SIZE_MAX)

static int do_txwb_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    
	if (priv->prd) {
		int			size = 0;
		const char	*ptr;
		int			dataSize = 0;
		const char	*pData;
		int			i;
#if 0
		printpkt("patern:%s data:%s\n ht:%x %x %d %d len:%d, pos (%p,%p,%p,%p), offset (%d, %d)"
			,((content_match_t *)(priv->r->ds_list[0]))->pattern_buf
			,priv->prd ? priv->prd : "NULL"
			,priv->ht.isrc, priv->ht.idst
			,priv->ht.psrc, priv->ht.pdst
			,priv->skb->len, priv->data, priv->doe_ptr, priv->prd, priv->end, priv->dlen, priv->offset);
#endif
		skip_space(priv->prd);
		ptr = priv->prd;

		while (*ptr != '@' && *ptr != '\r' && *ptr != '\n' && *ptr != ';' && *ptr != '&'
			&& *ptr != '<' && *ptr != '>' && *ptr != '=' && *ptr != 0xD && *ptr != 0xA
			&& *ptr != 0 && size < TXWB_SIZE_MAX && ptr < priv->end)
			ptr++, size++;
	
		if (size && size < TXWB_SIZE_MAX
			&& _is_all_digit(priv->prd, size, TXWB_SIZE_MAX)) {

			pData = priv->prd;
			dataSize = size;
			for (i = 0; i < size; i++) {
				if (priv->prd[i] == '0') {
					pData++;
					dataSize--;
					printpkt("Data is start with '0', ignore %d.", i);
				} else {
					break;
				}
			}

#if 0
			if (rule_dbg_lvl) {
			char tmp[65];
			int 	tmplen = 0;

			memset(tmp, 0, sizeof(tmp));
			tmplen = priv->offset > 64 ? 64 : (pData - priv->prd);
			memcpy(tmp, (pData-tmplen), tmplen);
			printpkt("offset: %d, %d, %d, pre header %d=[%s]",
				pData - priv->prd, priv->end-pData, priv->end-priv->prd, tmplen, tmp);
			}
#endif

			if ((priv->end - pData) <= dataSize) {
				printpkt("the account have no terminate char, discard it for safe!"
					"dataSize %d(%d).", dataSize, (priv->end - pData));
				return -1;
			}
			if (dataSize < TXWB_SIZE_MIN) {
				printpkt("dataSize %d is small than min %d, discard.", dataSize, TXWB_SIZE_MIN);
				return -1;
			}
            unsigned char buf[TXWB_SIZE_MAX] = {0};
            memcpy(buf,pData, dataSize);
            printf("txwb-->size:%d info:%s \n",size,buf);
			do_record_data(buf,dataSize,priv);
			// priv->ptl->msg.mc_add(priv->ptl, TXWB
			// 	, pData, dataSize, ip, mac);
			return 0;
		}
	}

	return -1;
}

PROTOCOL_CONTORL_INFO stTXWBCtrlInfo = {
    .strName        = "TXWB",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_txwb_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
