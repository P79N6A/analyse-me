/*
 * @Author: jiamu 
 * @Date: 2018-10-17 16:45:19 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-17 19:04:14
 */

#include "protocol.h"

#define MQQ_ENTRY_NUM	(32)
#define MQQ_SIZE_MAX	(16)
#define MQQ_SND_CYCLE	(HZ << 5) /* 32s */
#define MQQ_BUF_SIZE	(MQQ_ENTRY_NUM * MQQ_SIZE_MAX)
#define MQQ_LMARK_MIN	(0x05) /* 5 */
#define MQQ_LMARK_MAX	(0x0b) /* 11 */
#define MQQ_LMARK_DLT	(0x04)

static int do_mqq_action(int actionType,void *data)
{
    m_priv_t *priv	= data;
    if (priv->prd) {
		size_t size;
#if 0
{
	int i = 0;

	print("patern:%s\n ht:%x %x %d %d len:%d"
		,((content_match_t *)(priv->r->ds_list[0]))->pattern_buf
		,priv->ht.isrc, priv->ht.idst
		,priv->ht.psrc, priv->ht.pdst
		,priv->skb->len);

	for (i = 0; i < 50; i++)
		printk("%02x ", (uint8_t)priv->prd[i]);
	printk("\n");
}
#endif
		size = priv->prd[0] - MQQ_LMARK_DLT;
		if (MQQ_LMARK_MIN <= size
			&& size <= MQQ_LMARK_MAX 
			&& _is_all_digit(priv->prd + 1, size, MQQ_LMARK_MAX)) {
			// priv->ptl->msg.mc_add(priv->ptl, MQQ
			// 			, priv->prd + 1, size, ip, mac);
             unsigned char buf[MQQ_LMARK_MAX] = {0};
            memcpy(buf,priv->prd, size);
            printf("MQQ-->size:%d info:%s \n",size,buf);
			do_record_data(buf,size,priv);
			return 0;
		}
	}
	 return 0;
}
PROTOCOL_CONTORL_INFO stMQQCtrlInfo = {
    .strName        = "MQQ",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_mqq_action,
    .cbProtoPack    = NULL,
    .private        = NULL
};
