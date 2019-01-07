/*
 * @Author: jiamu 
 * @Date: 2018-09-27 15:19:49 
 * @Last Modified by: jiamu
 * @Last Modified time: 2019-01-07 15:44:34
 */




#include "im_config.h"
#include "daq_common.h"
#include "log.h"

//#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
NIDS_IF_INFO stIfInfo;
static unsigned int ulNetNum = 0;


extern int snort_do_detect(void *tuple,void *data,int slDataLen,int slProtocol,void *ethInfo,void * conn);
static inline int  set_stream_dir(struct tuple4 * addr,NIDS_CONNTRACK_RECORD *pstConn);

static ev_io io_watcher;

// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
char *
adres (struct tuple4 addr)
{
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ",%i,", addr.source);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ",%i", addr.dest);
  return buf;
}

void
tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{ 
  
	char buf[1024];
	struct tuple4 addr;
	struct ethhdr *pstEthInfo = &a_tcp->stEthInfo;
	struct ethhdr stEthInfo;
	NIDS_CONNTRACK_RECORD *pstConn = &a_tcp->stConnInfo;

  // fprintf (stderr,"Dst-->%02x:%02x:%02x:%02x:%02x:%02x \n"
  //            "Src-->%02x:%02x:%02x:%02x:%02x:%02x \n",
  //            pstEthInfo->h_dest[0],pstEthInfo->h_dest[1],pstEthInfo->h_dest[2],pstEthInfo->h_dest[3],pstEthInfo->h_dest[4],pstEthInfo->h_dest[5],
  //            pstEthInfo->h_source[0],pstEthInfo->h_source[1],pstEthInfo->h_source[2],pstEthInfo->h_source[3],pstEthInfo->h_source[4],pstEthInfo->h_source[5]);
	bzero(&addr,sizeof(addr));
	bzero(&stEthInfo,sizeof(stEthInfo));

  	strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
  	if (a_tcp->nids_state == NIDS_JUST_EST)
    {
		// connection described by a_tcp is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
		a_tcp->client.collect++; // we want data received by a client
		a_tcp->server.collect++; // and by a server, too
		a_tcp->server.collect_urg++; // we want urgent data received by a
                                   // server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
      	a_tcp->client.collect_urg++; // if we don't increase this value,
                                   // we won't be notified of urgent data
                                   // arrival
#endif
      	//fprintf (stderr, "%s established\n", buf);
      	return;
    }
  	if (a_tcp->nids_state == NIDS_CLOSE)
    {
		// connection has been closed normally
		//fprintf (stderr, "%s closing\n", buf);
		return;
    }
  	if (a_tcp->nids_state == NIDS_RESET)
    {
		// connection has been closed by RST
		//fprintf (stderr, "%s reset\n", buf);
		return;
    }

  if (a_tcp->nids_state == NIDS_DATA)
    {
		// new data has arrived; gotta determine in what direction
		// and if it's urgent or not

		struct half_stream *hlf;
		//int dir = 0;
		if (a_tcp->server.count_new_urg)
		{
			// new byte of urgent data has arrived 
			strcat(buf,"(urgent->)");
			buf[strlen(buf)+1]=0;
			buf[strlen(buf)]=a_tcp->server.urgdata;
			write(1,buf,strlen(buf));
			return;
		}
		// We don't have to check if urgent data to client has arrived,
		// because we haven't increased a_tcp->client.collect_urg variable.
		// So, we have some normal data to take care of.
		if (a_tcp->client.count_new)
		{
		// new data for client
			hlf = &a_tcp->client; // from now on, we will deal with hlf var,
						// which will point to client side of conn
			strcat (buf, "(<-)"); // symbolic direction of data
			//dir = 0;
			pstConn->slStreamIdRecv++;
			pstConn->eDir = IP_CT_DIR_REPLY;
			addr.saddr 	= a_tcp->addr.daddr;
			addr.daddr 	= a_tcp->addr.saddr;
			addr.source = a_tcp->addr.dest;
			addr.dest 	= a_tcp->addr.source;

			memcpy(stEthInfo.h_dest,pstEthInfo->h_source,6);
			memcpy(stEthInfo.h_source,pstEthInfo->h_dest,6);

			//printf("count %d offset %d bufsize %d \n",hlf->count,hlf->offset,hlf->bufsize);
		}
		else
		{
			hlf = &a_tcp->server; // analogical
			strcat (buf, "(->)");
			//dir = 1;
			pstConn->slStreamIdSend++;
			pstConn->eDir = IP_CT_DIR_ORIGINAL;
			addr = a_tcp->addr;
			stEthInfo = *pstEthInfo;
		}

		//set_stream_dir(&a_tcp->addr,pstConn);
		// fprintf (stderr,"tcp message data id -->%d diris:%s \n"
        //      "tuple info src:%08x dst:%08x \n",
		// 	 pstConn->eDir == IP_CT_DIR_ORIGINAL ? pstConn->slStreamIdSend : pstConn->slStreamIdRecv,
		// 	 pstConn->eDir == IP_CT_DIR_ORIGINAL ? "send":"recv",
		// 	 a_tcp->addr.saddr,a_tcp->addr.daddr
		// );
    	// fprintf (stderr,"tcp message data id -->%d diris:%s \n"
        //     "tuple info %s \n"
        //      "Dst-->%02x:%02x:%02x:%02x:%02x:%02x,port %d \n"
        //      "Src-->%02x:%02x:%02x:%02x:%02x:%02x,port %d \n",pstConn->eDir == IP_CT_DIR_ORIGINAL ? pstConn->slStreamIdSend : pstConn->slStreamIdRecv,pstConn->eDir == IP_CT_DIR_ORIGINAL ? "send":"recv",adres (a_tcp->addr),
        //      pstEthInfo->h_dest[0],pstEthInfo->h_dest[1],pstEthInfo->h_dest[2],pstEthInfo->h_dest[3],pstEthInfo->h_dest[4],pstEthInfo->h_dest[5],
        //      pstEthInfo->h_source[0],pstEthInfo->h_source[1],pstEthInfo->h_source[2],pstEthInfo->h_source[3],pstEthInfo->h_source[4],pstEthInfo->h_source[5]);
		//fprintf(stderr,"%s",buf); // we print the connection parameters
						// (saddr, daddr, sport, dport) accompanied
						// by data flow direction (-> or <-)
		//write(2,hlf->data,hlf->count_new); // we print the newly arrived data
		snort_do_detect(&addr,hlf->data,hlf->count_new,IPPROTO_TCP,&stEthInfo,pstConn);
    }
  return ;
}
void udp_callback(struct tuple4 * addr, char * buf, int len, struct ip * iph,void *ethInfo,void *conn)
{
	struct ethhdr *pstEthInfo = (struct ethhdr *)ethInfo;
	NIDS_CONNTRACK_RECORD *pstConn = (NIDS_CONNTRACK_RECORD *)conn;
	//pstConn->slStreamIdRecv++;
	//pstConn->eDir     = IP_CT_DIR_ORIGINAL;

	if(set_stream_dir(addr,pstConn) < 0)
	{
		print(
		     "Not lan stream src:%08x dst:%08x \n", addr->saddr,addr->daddr);
			 return;
	}

	// fprintf (stderr,"Udp message data id -->%d diris:%s\n"
	// "tuple info %s \n"
	// "Dst-->%02x:%02x:%02x:%02x:%02x:%02x \n"
	// "Src-->%02x:%02x:%02x:%02x:%02x:%02x \n",pstConn->eDir == IP_CT_DIR_ORIGINAL ? pstConn->slStreamIdSend : pstConn->slStreamIdRecv,
	// pstConn->eDir == IP_CT_DIR_ORIGINAL ? "send":"recv",
	// adres (*addr),
	// pstEthInfo->h_dest[0],pstEthInfo->h_dest[1],pstEthInfo->h_dest[2],pstEthInfo->h_dest[3],pstEthInfo->h_dest[4],pstEthInfo->h_dest[5],
	// pstEthInfo->h_source[0],pstEthInfo->h_source[1],pstEthInfo->h_source[2],pstEthInfo->h_source[3],pstEthInfo->h_source[4],pstEthInfo->h_source[5]);

	snort_do_detect(addr,buf,len,IPPROTO_UDP,ethInfo,pstConn);
}

static inline int  set_stream_dir(struct tuple4 * addr,NIDS_CONNTRACK_RECORD *pstConn)
{
	unsigned int ulSaddr = htonl(addr->saddr);
	unsigned int ulDaddr = htonl(addr->daddr);
	if(ulNetNum == (ulSaddr & stIfInfo.ulMask))
	{
		//printf("This is send stream \n");
		pstConn->eDir     = IP_CT_DIR_ORIGINAL;
		pstConn->slStreamIdSend++;
	}
	else if(ulNetNum == (ulDaddr & stIfInfo.ulMask))
	{
		//printf("This is recv stream \n");
		pstConn->eDir     = IP_CT_DIR_REPLY;
		pstConn->slStreamIdRecv++;
	}
	else
	{
		return RET_FAILED;
	}
    return RET_SUCCESS;
}

static void  init_stream_dir(void)
{	
	int num = 0,i = 0 ,j = 0;
	unsigned char ucBuf[1024] = {0};
	NIDS_IF_INFO *pstInfo = (NIDS_IF_INFO *)ucBuf;
	memset(&stIfInfo,0,sizeof(stIfInfo));

	num = nids_getif_info(NULL,ucBuf); /*should input nids_params.device*/
	if(num < 0)
	{
		fatal("get interface info failed \n");
	}
	
	for(i = 0;i < num;i++)
	{
		printf("Now get if:%s ip:%08x mask:%08x \n",pstInfo[i].ifName,pstInfo[i].ulIp,pstInfo[i].ulMask);
		if(strcasecmp(pstInfo[i].ifName,nids_params.device) == 0 && pstInfo[i].ulIp != 0)
		{
			j = 1;
			stIfInfo = pstInfo[i];
			ulNetNum = stIfInfo.ulIp & pstInfo[i].ulMask; /*actually stIfInfo.ulIp is netnum*/
			printf("capture interface is %s ulNetNum:%08x\n",pstInfo[i].ifName,ulNetNum);
		}
	}
	if(j == 0)
	{
		fatal("not find capture iterface %s \n",nids_params.device);
	}
}	

static void nids_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	nids_next ();
}

int daq_init(int mode,struct ev_loop *loop)
{
    nids_params.device 			= stIfInfo.ifName;
	nids_params.n_tcp_streams 	= 10240; 
	//nids_params.filename   		= "/tmp/139_4.pcapng";
	//printf("Now start handle %s \n",nids_params.filename);
	//nids_params.filename = "/tmp/check_imap.pcapng";
    if (!nids_init (loop))
    {
        fprintf(stderr,"%s\n",nids_errbuf);
        exit(1);
    }
    nids_register_udp (udp_callback);
    nids_register_tcp (tcp_callback);

	//init_stream_dir();
	ulNetNum = stIfInfo.ulIp & stIfInfo.ulMask;

    int fd = nids_getfd ();
    ev_io_init(&io_watcher, nids_read_cb, fd, EV_READ);
    ev_io_start(loop, &io_watcher);

    return 0;
}