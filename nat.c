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

#include <time.h>
#include "tcp.h"
#define BUF_SIZE	2048
#define DEBUG_MODE_UDP 1
#define MAX=2001;

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

char PORTARRY[2001];
int decision;
extern TCP_Table currentTable[MAX];



/************************************************************************\
                           UDP Part
\************************************************************************/

typedef struct UDP_NAT_TABLE_TYPE{
	unsigned int ipAddr; //vm b or c
	unsigned short port; 	//vm b or c
	unsigned short translated_port; //vm a
	double timestamp;
	char valid;
}UDP_NAT_TABLE_TYPE;

UDP_NAT_TABLE_TYPE UDP_NAT_TABLE[MAX];



void check_udp_entry_time_out() 
{
		struct udphdr * udph = ( struct udphdr *) ((( char *) ip )
		+ ip ->ihl *4) ;

		unsigned int ip_temp=0;
		unsigned short port_temp=0;

			if (( ntohl (ip -> saddr ) & LOCAL_MASK )== LOCAL_NETWORK ) 
			{
				//out
					ip_temp=ntohl(ip -> saddr);//can i?
					port_temp=ntohs(udph -> source);//can i?


					int i;
					for(i=0;i<MAX;i++)
					{
						

						if((ip_temp==UDP_NAT_TABLE[i].ipAddr)&&(port_temp==UDP_NAT_TABLE[i].port)&&(UDP_NAT_TABLE[i].valid==1))
						{
						double ts = msg -> timestamp_sec +( double )msg -> timestamp_usec /1000000;
						double time_difference=100;
						time_difference=ts-UDP_NAT_TABLE[i].timestamp;

							if(time_difference>30)
							{
								UDP_NAT_TABLE[i].valid=0;
								PORTARRY[i];
							}
							break;
						}
					}





			}

			else 
			{
				// in
						port_temp=ntohs(udph -> dest);//can i?

					int i;
					for(i=0;i<MAX;i++)
					{
						if((port_temp==UDP_NAT_TABLE[i].translated_port)&&(UDP_NAT_TABLE[i].valid==1))
						{
						double ts = msg -> timestamp_sec +( double )msg -> timestamp_usec /1000000;
						double time_difference=100;
						time_difference=ts-UDP_NAT_TABLE[i].timestamp;

							if(time_difference>30)
							{
								UDP_NAT_TABLE[i].valid=0;
								PORTARRY[i];
							}
							break;
						}
					}


			}
			
	

}


int UDP_Handling(){

int change=2;

struct udphdr * udph = ( struct udphdr *) ((( char *) ip )
		+ ip ->ihl *4) ;


if (( ntohl (ip -> saddr ) & LOCAL_MASK )== LOCAL_NETWORK ) {
// Out-bound traffic



/*step1:  search if the incoming packet has a source IP-port pair*/

		



		int match=0;
		int match_index=0;
		unsigned int ip_temp=0;
		unsigned short port_temp=0;

		int i;
		for(i=0;i<MAX;i++)
		{
			if((ip_temp==UDP_NAT_TABLE[i].ipAddr)&&(port_temp==UDP_NAT_TABLE[i].port)&&(UDP_NAT_TABLE[i].valid==1))
				{
					match=1;
					match_index=i;
					break;
				}
		}


/*step2: If yes, the NAT program should use the previously-assigned translated port number for the outbound packet.*/
		if(match)
		{

			/*step4:update information.*/
			// now translate and update header
		port_temp=UDP_NAT_TABLE[match_index].translated_port;
		port_temp=htons(port_temp);
		udph -> source=port_temp;

		public_IP=htonl(public_IP);
		ip -> saddr=public_IP;

		udph -> check=htons(udp_checksum(msg->payload));
		ip -> check=htons(ip_checksum(msg->payload));

		//refresh timestamp
		double ts = msg -> timestamp_sec +( double )msg -> timestamp_usec /1000000;

			UDP_NAT_TABLE[match_index].timestamp=ts;//need modify
		


			change=1;
			return change;
		}//end if yes

/*step3: If not, the NAT program should create new entry.*/

		else
		{

			

			ip_temp=ntohl(ip -> saddr);//can i?  vm b or c 
			port_temp=ntohs(udph -> source);//can i? vm b or c 

			
			unsigned short translated_port_temp=0;

			int i;
			for(i=0;i<2001;i++)
			{
				if(PORTARRY[i]==0)
				{
					PORTARRY[i]=1;
					translated_port_temp=10000+i;
				}

			}

			if(translated_port_temp=0)
			{
				printf("No available port!!!\n");
				return -1;

			}

			if(DEBUG_MODE_UDP)
				printf("Translated_port_temp is  %u\n", translated_port_temp);



			if((translated_port_temp<=12000)&&(10000<=translated_port_temp))
			{

					int i;
					for(i=0;i<MAX;i++)
					{
							if(UDP_NAT_TABLE[i].valid==0)
							{
								break;
							}	

					}



			UDP_NAT_TABLE[i].ipAddr=ip_temp;
			UDP_NAT_TABLE[i].port=port_temp;
			UDP_NAT_TABLE[i].translated_port=translated_port_temp;
			UDP_NAT_TABLE[i].valid=1;


			double ts = msg -> timestamp_sec +( double )msg -> timestamp_usec /1000000;

			UDP_NAT_TABLE[i].timestamp=ts;//need modify

			
			/*step4:update information.*/

			// now translate and update header
			port_temp=UDP_NAT_TABLE[i].translated_port;
			port_temp=htons(port_temp);
			udph -> source=port_temp;

			public_IP=htonl(public_IP);
			ip -> saddr=public_IP;



			
			udph -> check=htons(udp_checksum(msg->payload));
			ip -> check=htons(ip_checksum(msg->payload));
			

			change=1;
			return change;
			}
			else
			{

			printf("port number %d out of range\n", translated_port_temp);
			change=-1;
			return change;

			}





		}//end if not
}//end Out-bound traffic


else {
// In-bound traffic





	int match=0;
		int match_index=0;
		unsigned int ip_temp=0;
		unsigned short port_temp=0;
		port_temp=ntohs(udph -> dest);//can i?
		int i;
		for(i=0;i<MAX;i++)
		{
			if((port_temp==UDP_NAT_TABLE[i].translated_port)&&(UDP_NAT_TABLE[i].valid==1))
				{
					match=1;
					match_index=i;
					break;
				}
		}


		if(match)
		{

			/*step4:update information.*/
			// now translate and update header
		port_temp=UDP_NAT_TABLE[match_index].port;
		port_temp=htons(port_temp);
		udph -> dest=port_temp;

		ip_temp=UDP_NAT_TABLE[match_index].ipAddr;
		ip_temp=htonl(ip_temp);
		ip -> daddr=ip_temp;

		udph -> check=htons(udp_checksum(msg->payload));
		ip -> check=htons(ip_checksum(msg->payload));

		//refresh timestamp
		double ts = msg -> timestamp_sec +( double )msg -> timestamp_usec /1000000;

			UDP_NAT_TABLE[match_index].timestamp=ts;//need modify
	


			change=1;
			return change;
		}//end if yes
		else
		{
			change=-1;
			return change;
		}


}





return change;

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

void do_your_job(unsigned char *ip_pkt)
{


	pkt_count++;

	printf("[%5d] ", pkt_count);

	ip = (struct iphdr *) ip_pkt;
	switch(ip->protocol)
	{
	  case IPPROTO_TCP:
	  	decision=handle_tcp(ip, (struct tcphdr *) (((unsigned char *) ip) + ip->ihl * 4));
		break;

	  case IPPROTO_UDP:
		decision=UDP_Handling();
		break;

	  case :
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


// initialize 
		int i;
		for(i=0;i<MAX;i++)
		{
			currentTable[i].valid = 0;
			UDP_NAT_TABLE[i].valid = 0;
		}

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
		
		check_udp_entry_time_out();

		do_your_job(msg->payload);

		if(decision == -1){
			if(ipq_set_verdict(ipq_handle, msg->packet_id, NF_DROP, 0, NULL) == -1)
			{
			byebye("ipq_set_verdict");	// exit(1) included.
			}
		}else if(decision == 1){
			if(ipq_set_verdict(ipq_handle, msg->packet_id, NF_ACCEPT, msg->data_len, msg) == -1)
			{
			byebye("ipq_set_verdict");	// exit(1) included.
			}
		}else{
			if(ipq_set_verdict(ipq_handle, msg->packet_id, NF_ACCEPT, 0, NULL) == -1)
			{
			byebye("ipq_set_verdict");	// exit(1) included.
			}
		}

	} while(1);

	return 0;

} // end main()
