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

#include <sys/types.h>		// required by "inet_ntop()"
#include <sys/socket.h>		// required by "inet_ntop()"
#include <arpa/inet.h>		// required by "inet_ntop()"
#include "checksum.h"
#include "tcp.h"

#define tableMAX 500;
#define debugMode 1;

TCP_Table currentTable[tableMAX];

void checkTermination(int foundEntry){

	if(tcph->fin == 1 && tcph->ack != 1){
		if(currentTable[foundEntry]->exitFlow == -1){
			currentTable[foundEntry]->exitFlow = 1;
			if(debugMode){
				printf("FIN sent to initiate closing..\n");
			}
		}else if (currentTable[foundEntry]->exitFlow == 2){
			currentTable[foundEntry]->exitFlow = 3;
			if(debugMode){
				printf("FIN sent to respond to closing..\n");
			}
		}
	}

	if(tcph->fin == 1 && tcph->ack == 1){
		if(currentTable[foundEntry]->exitFlow == 1){
			currentTable[foundEntry]->exitFlow = 3;
			if(debugMode){
				printf("FIN & ACK sent together to respond to closing..\n");
			}
		}
	}

	if(tcph->ack == 1 && tcph->fin != 1){
		if(currentTable[foundEntry]->exitFlow == 1){
			currentTable[foundEntry]->exitFlow = 2;
			if (debugMode){
				printf("ACK sent to respond to closing..\n");
			}
		}else if(currentTable[foundEntry]->exitFlow == 3){
			currentTable[foundEntry]=NULL;
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
			if(currentTable[i] != NULL){
				if((currentTable[i]->originalIP == (ntohl(ip->saddr))) && (currentTable[i]->originalPort == (ntohs(tcph->source)))){
					foundEntry = i;
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
						if(currentTable[i]==NULL){
							insertEntry = i;
						}
					}

					if(insertEntry == -1){
						printf("Warning! There is no empty entry to be inserted!!\n");
						return -1;
					}else{
						currentTable[insertEntry] = malloc(sizeof(TCP_Table));
						currentTable[insertEntry]->originalIP = ntohl(ip->saddr);
						currentTable[insertEntry]->originalPort = ntohs(tcph->source);
						currentTable[insertEntry]->newPort = newPort;
						currentTable[insertEntry]->exitFlow = -1;

						if(debugMode){
							printf("Created new Entry table! NewPort: %d\n",newPort);
						}
						ip->saddr = htonl(public_IP);
						tcph->source = htons(currentTable[insertEntry]->newPort);

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
				tcph->source = htons(currentTable[foundEntry]->newPort);

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
			if(currentTable[i]!=NULL){
				if(currentTable[i]->newPort == (ntohs(tcph->dest))){
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
			ip->daddr = htonl(currentTable[foundEntry]->originalIP);
			tcph->dest = htons(currentTable[foundEntry]->originalPort);
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
				currentTable[foundEntry] = NULL;
			}

			return 1;
		}
	}
}



