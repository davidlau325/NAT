#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>		// required by "netfilter.h"
#include <linux/netfilter.h>	// required by NF_ACCEPT, NF_DROP, etc...
#include <libipq.h>		// required by ipq_* functions
#include <arpa/inet.h>		// required by ntoh[s|l]()
#include <signal.h>		// required by SIGINT
#include <string.h>		// required by strerror()

#include <netinet/ip.h>		// required by "struct iph"
#include <netinet/tcp.h>	// required by "struct tcph"
#include <netinet/udp.h>	// required by "struct udph"
#include <netinet/ip_icmp.h>	// required by "struct icmphdr"

#include <sys/types.h>		// required by "inet_ntop()"
#include <sys/socket.h>		// required by "inet_ntop()"
#include <arpa/inet.h>		// required by "inet_ntop()"
#include "tcp.h"
#define BUF_SIZE	2048
#define DEBUG_MODE_UDP 1
#define MAX=500;

/************************************************************************\
                           Global Variables
\************************************************************************/

struct ipq_handle *ipq_handle = NULL;	// The IPQ handle

unsigned int pkt_count = 0;		// Count the number of queued packets

/*I move them here to make them global variables*/

struct iphdr *ip; 

unsigned char buf[BUF_SIZE];	// buffer to stored queued packets

ipq_packet_msg_t *msg;		// point to the packet info.

struct in_addr * public_IP;

struct in_addr * LOCAL_NETWORK;

unsigned int  LOCAL_MASK;


char PORTARRY[2000];




/************************************************************************\
                           UDP Part
\************************************************************************/

typedef struct UDP_NAT_TABLE{
	unsigned int ipAddr;
	unsigned short port;
	unsigned short translated_port;
	double timestamp_last;
	double timestamp_create;
	int valid;
}UDP_NAT_TABLE;

UDP_NAT_TABLE[MAX];

int UDP_NAT_TABLE_count=0;




void UDP_Handling(){


if (( ntohl (ip -> saddr ) & LOCAL_MASK )== LOCAL_NETWORK ) {
// Out-bound traffic



		/*step1:  search if the incoming packet has a source IP-port pair*/

		struct udphdr * udph = ( struct udphdr *) ((( char *) ip )
		+ ip ->ihl *4) ;



		int match=0;
		int match_index=0;
		unsigned int ip_temp=0;
		unsigned short port_temp=0;

		int i;
		for(i=0;i<UDP_NAT_TABLE_count;i++)
		{
			ip_temp=ntohl(ip -> saddr);//can i?
			port_temp=ntohs(udph -> source);//can i?

			if((ip_temp==UDP_NAT_TABLE[i].ipAddr)&&(port_temp==UDP_NAT_TABLE[i].port))
				{
					match=1;
					match_index=i;
					break;
				}
		}


/*step2: If yes, the NAT program should use the previously-assigned translated port number for the outbound packet.*/
		if(match)
		{

		port_temp=UDP_NAT_TABLE[match_index].translated_port;
		port_temp=htons(port_temp);
		udph -> source=port_temp;

		public_IP=htonl(public_IP);
		ip -> saddr=public_IP;
		}

		else
		{

			UDP_NAT_TABLE_count++;

			ip_temp=ntohl(ip -> saddr);//can i?
			port_temp=ntohs(udph -> source);//can i?

			UDP_NAT_TABLE[UDP_NAT_TABLE_count-1].ipAddr=ip_temp;
			UDP_NAT_TABLE[UDP_NAT_TABLE_count-1].port=port_temp;

			if((UDP_NAT_TABLE[UDP_NAT_TABLE_count-2].translated_port+1<=12000)&&(0<=UDP_NAT_TABLE[UDP_NAT_TABLE_count-2].translated_port+1))
			UDP_NAT_TABLE[UDP_NAT_TABLE_count-1].translated_port=UDP_NAT_TABLE[UDP_NAT_TABLE_count-2].translated_port+1;
			else
				printf("port number %d out of range\n", UDP_NAT_TABLE[UDP_NAT_TABLE_count-2].translated_port+1);





		}

















}
else {
// In-bound traffic
}




double ts = msg -> timestamp_sec +
( double )msg -> timestamp_usec /1000000;




}



/************************************************************************\
                           Function Prototypes
\************************************************************************/

void byebye(char *msg);

void sig_handler(int sig);

void do_your_job(unsigned char *ip_pkt);




/************************************************************************\
                           Function Definitions
\************************************************************************/

/**
	Function: byebye

	Argument #1: char *msg
		The message that will be displayed as a part of the
		error message.

		if msg == NULL, then there will be no error message
		printed.

	Description:
		1) destroy the IPQ handle;
		2) Flush the iptables to free all the queued packets;
		3) print the error message (if any).
 **/

void byebye(char *msg) {
	if(ipq_handle)
		ipq_destroy_handle(ipq_handle);

	system("/sbin/iptables -F");
	printf("\n  iptables flushed.\n");

	if(msg != NULL) {		// I have something to say.
		printf("Number of processed packets: %u\n", pkt_count);
		ipq_perror(msg);
		exit(1);
	}
	else {			// I have nothing to say.
		printf("  Number of processed packets: %u\n", pkt_count);
		puts("  Goodbye.");
		exit(0);
	}
}

void sig_handler(int sig) {
	if(sig == SIGINT)
		byebye(NULL);
}

/****
	Function: do_your_job

	Argument #1: unsigned char *ipq_pkt;
		The pointer that points to the start of the IPQ packet 
		structure;

	Description:
		In this example, we print all the details about the 
		queued packet.
 */

void do_your_job(unsigned char *ip_pkt)
{


	pkt_count++;

	printf("[%5d] ", pkt_count);

	ip = (struct iphdr *) ip_pkt;
	switch(ip->protocol)
	{
	  case IPPROTO_TCP:
		 // handling TCP here!
	  	  handle_tcp(ip, (struct tcphdr *) (((unsigned char *) ip) + ip->ihl * 4));

		break;

	  case IPPROTO_UDP:
		UDP_Handling();
		break;

	  case IPPROTO_ICMP:
		// reserve for ICMP error handling
		break;

	  default:
		printf("Unsupported protocol\n");
	}

} // end do_your_job()


int main(int argc, char **argv)
{

	if(argc!=4)
	{

		printf("Usage: ./nat [public IP] [internal IP] [netmask] \n");
		exit(0);
	}
	else
	{
		public_IP=inet_aton(argv[1]);
		LOCAL_NETWORK=inet_aton(argv[2]);
		LOCAL_MASK=argv[3];
	}
	
	memset(PORTARRY,0,sizeof(char)*2000);



  /**** Create the ipq_handle ****/

	if( (ipq_handle = ipq_create_handle(0, PF_INET)) == NULL)
	{
		byebye("ipq_create_handle");	// exit(1) included.
	}

  /**** ipq_set_mode: I want the entire packet ****/

	if(ipq_set_mode(ipq_handle, IPQ_COPY_PACKET, BUF_SIZE) == -1)
	{
		byebye("ipq_set_mode");	// exit(1) included.
	}

	signal(SIGINT, sig_handler);	// Handle Ctrl + C.

	printf("Program: %s is ready\n", argv[0]);

	do
	{
	  /**** Read the packet from the QUEUE ****/

		if(ipq_read(ipq_handle, buf, BUF_SIZE, 0) == -1)
			byebye("ipq_read");	// exit(1) included

	  /**** Check whether it is an error or not ****/

		if(ipq_message_type(buf) == NLMSG_ERROR)
		{
			fprintf(stderr,
				"Error - ipq_message_type(): %s (errno = %d).\n",
				strerror(ipq_get_msgerr(buf)),
				ipq_get_msgerr(buf));
			exit(1);
		}

	  /**** This is the way to read the packet content ****/

		msg = ipq_get_packet(buf);

		do_your_job(msg->payload);

		if(ipq_set_verdict(ipq_handle, msg->packet_id, NF_ACCEPT, 0, NULL) == -1)
		{
			byebye("ipq_set_verdict");	// exit(1) included.
		}

	} while(1);

	return 0;

} // end main()
