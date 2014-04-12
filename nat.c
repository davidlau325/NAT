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

#include "checksum.h"
#include "tcp.h"

#define BUF_SIZE 2048
#define DEBUG_MODE_UDP 1
#define MAX 2001
#define tableMAX = 2000
#define debugMode = 1

/************************************************************************\
                           Global Variables
\************************************************************************/
// extern TCP_Table currentTable[MAX];

typedef struct UDP_NAT_TABLE_TYPE{
	unsigned int ipAddr; //vm b or c
	unsigned short port; 	//vm b or c
	unsigned short translated_port; //vm a
	double timestamp;
	char valid;
}UDP_NAT_TABLE_TYPE;

typedef struct TCP_Table{
	unsigned int originalIP;
	unsigned short originalPort;
	unsigned short newPort;
	int exitFlow;
	int valid;
}TCP_Table;

struct ipq_handle *ipq_handle = NULL;	// The IPQ handle
unsigned int pkt_count = 0;		// Count the number of queued packets

/*I move them here to make them global variables*/
struct iphdr *ip; 
unsigned char buf[BUF_SIZE];	// buffer to stored queued packets
ipq_packet_msg_t *msg;		// point to the packet info.
unsigned int public_IP;
unsigned int LOCAL_NETWORK;
unsigned int  LOCAL_MASK;

char PORTARRY[2001];
int decision;
UDP_NAT_TABLE_TYPE UDP_NAT_TABLE[MAX];
TCP_Table currentTable[tableMAX];

/************************************************************************\
                           TCP Part
\************************************************************************/

void checkTermination(int foundEntry){

	if(tcph->fin == 1 && tcph->ack != 1){
		if(currentTable[foundEntry].exitFlow == -1){
			currentTable[foundEntry].exitFlow = 1;
			if(debugMode){
				printf("FIN sent to initiate closing..\n");
			}
		}else if (currentTable[foundEntry].exitFlow == 2){
			currentTable[foundEntry].exitFlow = 3;
			if(debugMode){
				printf("FIN sent to respond to closing..\n");
			}
		}
	}

	if(tcph->fin == 1 && tcph->ack == 1){
		if(currentTable[foundEntry].exitFlow == 1){
			currentTable[foundEntry].exitFlow = 3;
			if(debugMode){
				printf("FIN & ACK sent together to respond to closing..\n");
			}
		}
	}

	if(tcph->ack == 1 && tcph->fin != 1){
		if(currentTable[foundEntry].exitFlow == 1){
			currentTable[foundEntry].exitFlow = 2;
			if (debugMode){
				printf("ACK sent to respond to closing..\n");
			}
		}else if(currentTable[foundEntry].exitFlow == 3){
			currentTable[foundEntry].valid = 0;
			if(debugMode){
				printf("The final ACK received and thus terminate this TCP flow!\n");
			}
		}
	}
}

int handle_tcp(){
	unsigned char *ip_pkt = msg->payload;
	struct iphdr *ip;
	int i;
	int foundEntry;
	int insertEntry;
	int newPort = -1;

	ip = (struct iphdr *) ip_pkt;
	struct tcphdr *tcph = (struct tcphdr *) (((unsigned char *) ip) + ip->ihl * 4);

	struct in_addr sip, dip;
	char sip_str[INET_ADDRSTRLEN+1], dip_str[INET_ADDRSTRLEN+1];

	sip.s_addr = ip->saddr;
	dip.s_addr = ip->daddr;

	if(!inet_ntop(AF_INET, &sip, sip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in source IP\n");
		return -1;
	}

	if(!inet_ntop(AF_INET, &dip, dip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in destination IP\n");
		return -1;
	}

	if(ntohl(ip->daddr) == public_IP){
			printf("Packet sent to VM A! No modified and just forward it!\n");
			return 2;
	}

	if((ntohl(ip->saddr) & LOCAL_MASK)==LOCAL_NETWORK){
		// out-bound packet

		foundEntry = -1;

		for(int i=0;i<tableMAX;i++){
			if(currentTable[i].valid == 1){
				if((currentTable[i].originalIP == (ntohl(ip->saddr))) && (currentTable[i].originalPort == (ntohs(tcph->source)))){
					foundEntry = i;
					break;
				}
			}
		}

		if(foundEntry == -1){
			if(tcph->syn == 1){
				if(debugMode == 1){
					printf("Received a SYN packet && Not found in Table Entry\n");
				}

				newPort = -1;
				for(i=0;i<2001;i++){
					if(PORTARRAY[i] == 0){
						newPort = (i+10000);
					}
				}

				if(newPort == -1){
					printf("No new Port available!\n");
					return -1;
				}else{
					insertEntry = -1;
					for(i=0;i<tabeMAX;i++){
						if(currentTable[i].valid == 1){
							insertEntry = i;
						}
					}

					if(insertEntry == -1){
						printf("Warning! There is no empty entry to be inserted!!\n");
						return -1;
					}else{
						currentTable[insertEntry] = malloc(sizeof(TCP_Table));
						currentTable[insertEntry].originalIP = ntohl(ip->saddr);
						currentTable[insertEntry].originalPort = ntohs(tcph->source);
						currentTable[insertEntry].newPort = newPort;
						currentTable[insertEntry].exitFlow = -1;
						currentTable[insertEntry].valid = 1;

						if(debugMode){
							printf("Created new Entry table! NewPort: %d\n",newPort);
						}
						ip->saddr = htonl(public_IP);
						tcph->source = htons(currentTable[insertEntry].newPort);

						ip->check = htons(ip_checksum(msg->payload));
						tcph->check = htons(tcp_checksum(msg->payload));

						return 1;
					}
				}
			}else{
				if(debugMode){
					printf("Received Not a SYN packet && Not found in Table Entry\n");
					printf("Drop the packer!\n");
				}
				return -1;
			}
		}else{
			if(tcph->syn == 1){
				if(debugMode){
					printf("Warning!! Received a SYN packet && found in Table Entry, impossible! Dropped!\n");
				}
				return -1;
			}else{
				if(debugMode){
					printf("Received Not a SYN packet && found in Table Entry\n");
				}
				ip->saddr = htonl(public_IP);
				tcph->source = htons(currentTable[foundEntry].newPort);

				ip->check = htons(ip_checksum(msg->payload));
				tcph->check = htons(tcp_checksum(msg->payload));

				if(debugMode){
					printf("TCP IP address and Port Modified as retrieved from table= Port: %d",ntohs(tcph->source));
				}

				checkTermination(foundEntry);
				
				return 1;
			}
		}
	}else{
		// in-bound packet

		foundEntry = -1;
		for(i=0;i<tableMAX;i++){
			if(currentTable[i].valid == 1){
				if(currentTable[i].newPort == (ntohs(tcph->dest))){
					foundEntry = i;
					break;
				}
			}
		}

		if(foundEntry == -1){
			if(debugMode == 1){
					printf("Dropped TCP in-bound packet because no entry found!\n");
			}
			return -1;
		}else{
			ip->daddr = htonl(currentTable[foundEntry].originalIP);
			tcph->dest = htons(currentTable[foundEntry].originalPort);
			ip->check = htons(ip_checksum(msg->payload));
			tcph->check = htons(tcp_checksum(msg->payload));

			if(debugMode){
					printf("Entry found! Modified in-bound packet!\n");
			}

			checkTermination(foundEntry);

			if(tcph->rst == 1){
				if(debgMode){
					printf("The in-bound packet is a RST packet, translated done but dropped the entry\n");
				}
				currentTable[foundEntry].valid = 0;
			}

			return 1;
		}
	}
}


/************************************************************************\
                           UDP Part
\************************************************************************/


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
								PORTARRY[i]=0;
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
								PORTARRY[i]=0;
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
					break;
				}

			}

			if(translated_port_temp==0)
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

						if(i==MAX)
						{

							printf("No available NAT entry!!!\n");
							return -1;


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
	}else {
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
	  	printf("Hello World\n");
		break;

	  case IPPROTO_UDP:
		decision=UDP_Handling();
		break;

	  case IPPROTO_ICMP:
		printf("This is ICMP packet\n");
		break;

	  default:
		printf("Unsupported protocol\n");
	}

} 


int main(int argc, char **argv)
{
	struct in_addr* container = malloc(sizeof(struct in_addr));
	if(argc!=4)
	{
		printf("Usage: ./nat [public IP] [internal IP] [netmask] \n");
		exit(0);
	}
	else
	{
		inet_aton(argv[1],container);
		public_IP = container->s_addr;
                inet_aton(argv[2],container);
		LOCAL_NETWORK=container->s_addr;
		LOCAL_MASK=atoi(argv[3]);
	}
	
	memset(PORTARRY,0,sizeof(char)*2001);


// initialize 
		int i;
		for(i=0;i<MAX;i++)
		{
			//currentTable[i].valid = 0;
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
			if(ipq_set_verdict(ipq_handle, msg->packet_id, NF_ACCEPT, msg->data_len, msg->payload) == -1)
			{
			byebye("ipq_set_verdict");	// exit(1) included.
			}
		}else{
			if(ipq_set_verdict(ipq_handle, msg->packet_id, NF_ACCEPT, 0, NULL) == -1)
			{
			byebye("ipq_set_verdict");	// exit(1) included.
			}
		}

	}while(1);

	return 0;
}
