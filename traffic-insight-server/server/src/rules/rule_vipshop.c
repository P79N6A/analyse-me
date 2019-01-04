/*
 * @Author: jiamu 
 * @Date: 2018-10-16 10:28:35 
 * @Last Modified by: jiamu
 * @Last Modified time: 2018-10-19 16:17:03
 */
#include "protocol.h"



#define VIPSHOP_ENTRY_NUM		(8)
#define VIPSHOP_SIZE_MAX		(16)
#define VIPSHOP_SIZE_MIN		(5)
#define VIPSHOP_RUID_SIZE		(9 + 9)	// vipruid=172755803
#define VIPSHOP_SND_CYCLE		(HZ << 5) /* 32s */
#define VIPSHOP_BUF_SIZE		(VIPSHOP_ENTRY_NUM * VIPSHOP_SIZE_MAX)


static int do_vipshop_action(int actionType,void *data)
{
    m_priv_t *pstPri	= ( m_priv_t *)data;

    //print("Now get one vipshop data stream %s !!!!!!!\n",pstPri->prd ? pstPri->prd : "Not right");
	if (pstPri->prd) {
		int			size = 0;
		const char	*ptr, *headptr, *idptr = NULL;
		const char	*idstr = "vipruid=";
#if 0
		printpkt("patern:%s data:%s\n ht:%x %x %d %d len:%d"
			,((content_match_t *)(pstPri->r->ds_list[0]))->pattern_buf
			,pstPri->prd ? pstPri->prd : "NULL"
			,pstPri->ht.isrc, pstPri->ht.idst
			,pstPri->ht.psrc, pstPri->ht.pdst
			,pstPri->skb->len);
#endif
		skip_space(pstPri->prd);
		ptr = pstPri->prd;
		headptr = pstPri->prd;

REPASER:
		while (*ptr != '&' && *ptr != ' ' && *ptr != ';' && *ptr != '%' && *ptr != '*'
			&& *ptr != 0 && size < VIPSHOP_SIZE_MAX && ptr < pstPri->end)
			ptr++, size++;

		// phone NO. is encrypt 
		if (idptr == NULL && *ptr == '*' && size >= 3 && size < 5 
			&& (ptr+VIPSHOP_RUID_SIZE)<pstPri->end) {
			//printpkt("phone NO. is encrypt = [%s]",ptr);
			idptr = strnstr(ptr+1, idstr, pstPri->end-ptr-1);
			if (idptr) {
				idptr += strlen(idstr);
				ptr = idptr;
				size = 0;
				headptr = idptr;
				//printpkt("found ruid data: %s",idptr);
				goto REPASER;
			}
		}

		if (size && size < VIPSHOP_SIZE_MAX && size > VIPSHOP_SIZE_MIN
			&& _is_all_digit(headptr, size, VIPSHOP_SIZE_MAX)) {
			// pstPri->ptl->msg.mc_add(pstPri->ptl, VIPSHOP
			// 			, headptr, size, ip, mac);
			unsigned char buf[VIPSHOP_SIZE_MAX + 10] = {0};
            memcpy(buf,headptr, size);
            //printf("vipshop---> size:%d msg:%s \n",size,buf);
			do_record_data(buf,size,pstPri);
			//printpkt("headptr size %d = [%s]",size,headptr);
			return RET_SUCCESS;
		}
		//printpkt("report failed, size %d", size);
	}
	return RET_FAILED;
}





static int do_vipshop_pack(void *buf,int slBufLen)
{
    return RET_SUCCESS;
}


PROTOCOL_CONTORL_INFO stVIPSHOPCtrlInfo = {
    .strName        = "VIPSHOP",
    .slMsgNum       = 0,
    .cbProtoHandle  = do_vipshop_action,
    .cbProtoPack    = do_vipshop_pack,
    .private        = NULL
};

