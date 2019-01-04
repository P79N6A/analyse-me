/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "nids.h"
#include <ev.h>

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

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
   struct ethhdr *pstEthInfo = &a_tcp->stEthInfo;

  fprintf (stderr,"\nDst-->%02x:%02x:%02x:%02x:%02x:%02x \n"
             "Src-->%02x:%02x:%02x:%02x:%02x:%02x \n",
             pstEthInfo->h_dest[0],pstEthInfo->h_dest[1],pstEthInfo->h_dest[2],pstEthInfo->h_dest[3],pstEthInfo->h_dest[4],pstEthInfo->h_dest[5],
             pstEthInfo->h_source[0],pstEthInfo->h_source[1],pstEthInfo->h_source[2],pstEthInfo->h_source[3],pstEthInfo->h_source[4],pstEthInfo->h_source[5]);

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
      fprintf (stderr, "%s established\n", buf);
      return;
    }
  if (a_tcp->nids_state == NIDS_CLOSE)
    {
      // connection has been closed normally
      fprintf (stderr, "%s closing\n", buf);
      return;
    }
  if (a_tcp->nids_state == NIDS_RESET)
    {
      // connection has been closed by RST
      fprintf (stderr, "%s reset\n", buf);
      return;
    }

  if (a_tcp->nids_state == NIDS_DATA)
    {
      // new data has arrived; gotta determine in what direction
      // and if it's urgent or not

      struct half_stream *hlf;

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
	}
      else
	{
	  hlf = &a_tcp->server; // analogical
	  strcat (buf, "(->)");
	}
    fprintf(stderr,"%s",buf); // we print the connection parameters
                              // (saddr, daddr, sport, dport) accompanied
                              // by data flow direction (-> or <-)

   //write(2,hlf->data,hlf->count_new); // we print the newly arrived data
      
    }
  return ;
}

static void nids_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	nids_next ();
}
static ev_io io_watcher;
static struct ev_loop *eventLoop;
int 
main ()
{
  int time = 0;
  fd_set rset;
  struct timeval tv;

   printf("Use select \n");
   eventLoop = ev_default_loop(0);
  // here we can alter libnids params, for instance:
  // nids_params.n_hosts=256;
  if (!nids_init ())
  {
  	fprintf(stderr,"%s\n",nids_errbuf);
  	exit(1);
  }
  nids_register_tcp (tcp_callback);
  //nids_run();

  int fd = nids_getfd ();
  ev_io_init(&io_watcher, nids_read_cb, fd, EV_READ);
  ev_io_start(eventLoop, &io_watcher);
  // for (;;)
  //   {
  //     tv.tv_sec = 1;
  //     tv.tv_usec = 0;
  //     FD_ZERO (&rset);
  //     FD_SET (fd, &rset);
  //     // add any other fd we need to take care of
  //     if (select (fd + 1, &rset, 0, 0, &tv))
	//     {
  //       	if (FD_ISSET(fd,&rset))  // need to test it if there are other
  //       				// fd in rset
	// 		      if (!nids_next ())
  //              break;
	//     }
  //     else
  //     {
	//       fprintf (stderr, "%i ", time++);
  //     }

  //   }
  ev_loop(eventLoop, 0);
  return 0;
}
