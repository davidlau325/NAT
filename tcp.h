#ifndef TCP_H
#define TCP_H

extern ipq_packet_msg_t *msg;
extern unsigned int public_IP;
extern unsigned int LOCAL_NETWORK;
extern unsigned int LOCAL_MASK;
extern char PORTARRAY[2001];

struct TCPEntry{
	unsigned int originalIP;
	unsigned short originalPort;
	unsigned short newPort;
	int exitFlow;
};

typedef struct TCPEntry TCP_Table;

int handle_tcp()

#endif