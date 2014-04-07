/**
  The purpose of this program is to print the details of the captured
  IP packets.
 **/
//ssh -p 13015 csci4430@projgw.cse.cuhk.edu.hk
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

#define BUF_SIZE	2048


/************************************************************************\
                           Global Variables
\************************************************************************/

struct ipq_handle *ipq_handle = NULL;	// The IPQ handle

unsigned int pkt_count = 0;		// Count the number of queued packets

/************************************************************************\
                           Function Prototypes
\************************************************************************/

void byebye(char *msg);

void sig_handler(int sig);

void print_tcp(struct iphdr *ip, struct tcphdr *tcp);

void print_udp(struct iphdr *ip, struct udphdr *udp);

void print_icmp(struct iphdr *ip, struct icmphdr *icmp);

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

/**
	Function: sig_handler

	Argument #1:
		the numerical representation of the incoming signal.

	Description:
		To termination the program through the "byebye" function.
 **/

void sig_handler(int sig) {
	if(sig == SIGINT)
		byebye(NULL);
}

/**
	Function: print_tcp

	Argument #1: struct iphdr *ip
		The pointer that points to the start of the IP header.

	Argument #2: struct tcphdr *tcp
		The pointer that points to the start of the TCP header.

	Description:
		A **helper function** of the do_your_job() function.
		It is for printing the content of the TCP header.
 **/

void print_tcp(struct iphdr *ip, struct tcphdr *tcp)
{
	struct in_addr sip, dip;
	char sip_str[INET_ADDRSTRLEN+1], dip_str[INET_ADDRSTRLEN+1];

	sip.s_addr = ip->saddr;
	dip.s_addr = ip->daddr;

	if(!inet_ntop(AF_INET, &sip, sip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in source IP\n");
		byebye(NULL);
	}

	if(!inet_ntop(AF_INET, &dip, dip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in destination IP\n");
		byebye(NULL);
	}

  /**** IP ADDRESSES and PORT NUMBER *****/

	printf("TCP;\tSource: %s (%d)\tDestination: %s (%d)\n", 
		sip_str, ntohs(tcp->source),
		dip_str, ntohs(tcp->dest) );

  /**** TCP Flags *****/

	printf("\tTCP flags: ");
	fflush(stdout);

	if(tcp->urg)
		putchar('U');
	else
		putchar('_');

	if(tcp->ack)
		putchar('A');
	else
		putchar('_');

	if(tcp->psh)
		putchar('P');
	else
		putchar('_');

	if(tcp->rst)
		putchar('R');
	else
		putchar('_');

	if(tcp->syn)
		putchar('S');
	else
		putchar('_');

	if(tcp->fin)
		putchar('F');
	else
		putchar('_');

  /**** SEQ and ACK Number *****/

	printf("\tSEQ: %lu\tACK: %lu\n",
		(unsigned long) ntohl(tcp->seq),
		(unsigned long) ntohl(tcp->ack_seq));
	fflush(stdout);

}  // end print_tcp()




/****
	Function: print_udp

	Argument #1: struct iphdr *ip
		The pointer that points to the start of the IP header.

	Argument #2: struct tcphdr *udp
		The pointer that points to the start of the UDP header.

	Description:
		A **helper function** of the do_your_job() function.
		It is for printing the content of the UDP header.
 */

void print_udp(struct iphdr *ip, struct udphdr *udp)
{
	struct in_addr sip, dip;
	char sip_str[INET_ADDRSTRLEN+1], dip_str[INET_ADDRSTRLEN+1];

	sip.s_addr = ip->saddr;
	dip.s_addr = ip->daddr;

	if(!inet_ntop(AF_INET, &sip, sip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in source IP\n");
		byebye(NULL);
	}

	if(!inet_ntop(AF_INET, &dip, dip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in destination IP\n");
		byebye(NULL);
	}

  /**** IP ADDRESSES and PORT NUMBER *****/

	printf("UDP\tSource: %s (%d)\tDestination: %s (%d)\n", 
		sip_str,	ntohs(udp->source),
		dip_str, ntohs(udp->dest) );

  /**** LENGTH ****/

	printf("\tLength: %d\n", ntohs(udp->len));

}  // end print_udp()




/****
	Function: print_icmp

	Argument #1: struct iphdr *ip
		The pointer that points to the start of the IP header.

	Argument #2: struct tcphdr *icmp
		The pointer that points to the start of the ICMP header.

	Description:
		A **helper function** of the do_your_job() function.
		It is for printing the content of the ICMP header.
 */

void print_icmp(struct iphdr *ip, struct icmphdr *icmp)
{
	struct in_addr sip, dip;
	char sip_str[INET_ADDRSTRLEN+1], dip_str[INET_ADDRSTRLEN+1];

	sip.s_addr = ip->saddr;
	dip.s_addr = ip->daddr;

	if(!inet_ntop(AF_INET, &sip, sip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in source IP\n");
		byebye(NULL);
	}

	if(!inet_ntop(AF_INET, &dip, dip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in destination IP\n");
		byebye(NULL);
	}

  /**** IP ADDRESSES and PORT NUMBER *****/

	printf("ICMP\tSource: %s\tDestination: %s\n", 
		sip_str, dip_str);

} // end print_icmp




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
	struct iphdr *ip;

	pkt_count++;

	printf("[%5d] ", pkt_count);

	ip = (struct iphdr *) ip_pkt;
	switch(ip->protocol)
	{
	  case IPPROTO_TCP:
		print_tcp(ip, (struct tcphdr *)
				(((unsigned char *) ip) + ip->ihl * 4));
		break;

	  case IPPROTO_UDP:
		print_udp(ip, (struct udphdr *)
				(((unsigned char *) ip) + ip->ihl * 4));
		break;

	  case IPPROTO_ICMP:
		print_icmp(ip, (struct icmphdr *)
				(((unsigned char *) ip) + ip->ihl * 4));
		break;

	  default:
		printf("Unsupported protocol\n");
	}

} // end do_your_job()




/************************************************************************\

                           Main Function

\************************************************************************/

int main(int argc, char **argv)
{
	unsigned char buf[BUF_SIZE];	// buffer to stored queued packets
	ipq_packet_msg_t *msg;		// point to the packet info.

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
