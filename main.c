#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

enum Proto {
	IcmpProto = 1,
	IgmpProto = 2,
	TcpProto = 6,
	UdpProto = 17,
} ;

static void hndlpacket( int);

static void hndlip();

static void hndltcp(*, int);
static void hndludp(unsigned char *, int);
static void hndlicmp(unsigned char *, int);

/* Always current packet raw data. */
static unsigned char *buf;
/* Always current size of all packet. */
static unsigned int size;
/* Always current IP header. */
static struct iphdr *iph;
static struct sockaddr_in src, dest;

int
main(int argc, char *argv[]){
	int saddr_size, data_size;
	struct sockaddr saddr;
	struct in_addr in;
	buf = malloc(256*256) ;

	logfile = fopen("log.txt", "w") ;
	if(logfile==NULL){
		puts("Unable to create log file.");
	}

	puts("Starting...");

	puts("Getting socket...");
	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP) ;
	if(sock_raw < 0){
		printf("Socket error.");
		return 1 ;
	}

	puts("Starting main loop...");
	while(1){
		saddr_size = sizeof saddr ;

		/* Recieve packet. */
		data_size = recvfrom(sock_raw, buf, 256*256, 0, &saddr, &saddr_size) ;
		if( data_size < 0 ){
			puts("recvfrom error, failed to get packets");
			return 1 ;
		}

		/* Packet processing */
		hndlpacket(buf, data_size);
	}
	close(sock_raw);
	puts("Finished.");
	return 0 ;
}

void hndlpacket(unsigned char *buf, int size){
	struct iphdr *iph = (struct iphdr *)buf ;
	switch(iph->protocol){
	case TcpProto :
		hndltcp();
	break;
	case IcmpProto :
		hndlicmp();
	break;
	case IgmpProto :
		hndligmp();
	break;
	case UdpProto :
		hndludp(buf, size);
	break;
	default:
	}

void
hndlip()
{
	struct iphdr *iph = (struct iphdr *)buf ;

	memset(&src, 0, sizeof(src));
	src.sin_addr.s_addr = iph->saddr ;

	printf("{");
	printf("\"version\": %d,", (unsigned int)iph->version);
	if(iph->version == 4){
		size = iphdr->tot_len ;
		printf("\"len\":%d,", (unsigned int)iph->ihl);
		printf("\"tos\":%d,", (unsigned int)iph->tos );
		printf("\"id\":%d,", ntohs(iph->id));
		/*printf("\"reserved_zero\":%d,\n", (unsigned int)iph->ip_reserved_zero);
		printf("\"dont_fragment\":%d,", (unsigned int)iph->ip_dont_fragment);
		printf("\"more fragment\":%d,", (unsigned int)iph->ip_more_fragment);*/
		printf("\"ttl\":%d,", (unsigned int)iph->ttl);
		printf("\"proto\":%d,", (unsigned int)iph->protocol);
		printf("\"cksum\":%d,", (unsigned int)ntohs(iph->check));
		printf("\"src\":\"%s\",", inet_ntoa(src.sin_addr));
		printf("\"dst\":\"%s\",", inet_ntoa(dest.sin_addr));
	} else if(iph->version == 6) {
		/* Maybe later. (no)*/
	}
	printf("}");
}

void
hndltcp()
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)buf ;
	iphdrlen = iph->ihl*4 ;

	struct tcphdr *tcph = (struct tcphdr *)(buf + iphdrlen) ;

	hndlip();
	printf(",{");
	printf("\"src\":%u,", ntohs(tcph->source));
	printf("\"dst\":%u,", ntohs(tcph->dest));
	printf("\"seq:%u,", ntohl(tcph->seq));
	printf("\"ack_seq\":%u,", ntohl(tcph->ack_seq));
	printf("\"len\":%d,", (unsigned int)tcph->doff*4);
	printf("\"urgent_flag\":%d,", (unsigned int)tcph->urg);
	printf("\"ack\":%d,", (unsigned int)tcph->ack);
	printf("\"psh\":%d,", (unsigned int)tcph->psh);
	printf("\"rst\":%d,", (unsigned int)tcph->rst);
	printf("\"fin\":%d,", (unsigned int)tcph->fin);
	printf("\"win\":%d,", htons(tcph->window));
	printf("\"ck\":%d,", ntohs(tcph->check));
	printf("\"urg_ptr\":%d,", tcph->urg_ptr);
	printf("}")
	fhexdump( buf, iphdrlen);

	fprintf( "TCP header:");
	fhexdump( buf+iphdrlen, tcph->doff*4 );

	fprintf( "\nData payload:");
	fhexdump( buf + iphdrlen + tcph->doff*4, (size - tcph->doff*4 - iph->ihl*4 ));
}

void printUdpPacket(unsigned char *buf, int size){
	printdbg("\nIn 'printUdpPacket'\n");
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)buf ;
	iphdrlen = iph->ihl*4;

	struct udphdr *udph = (struct udphdr *)(buf + iphdrlen) ;
	fprintf( "\n\n******************* UDP packet ***************************");
	printIpHeader(buf, size);

	fprintf( "\nUDP header\n");
	fprintf( "    |-Source port       : %d\n", ntohs(udph->source));
	fprintf( "    |-UDP length        : %d\n", ntohs(udph->len));
	fprintf( "    |-UDP checksum      : %d\n", ntohs(udph->check));

	fprintf( "\n");
	fprintf( "IP header:\n");
	fhexdump( buf, iphdrlen);

	fprintf( "UDP header:\n");
	fhexdump( buf+iphdrlen, sizeof(udph));

	fprintf( "\nData payload:\n");
	fhexdump( buf + iphdrlen + sizeof(udph), (size - sizeof(udph) - iph->ihl*4 ));
}

void printIcmpPacket(unsigned char *buf, int size){
	printdbg("\nIn 'printIcmpPacket'\n");
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)buf;
	iphdrlen = iph->ihl*4 ;

	struct icmphdr *icmph = (struct icmphdr *)(buf + iphdrlen) ;

	fprintf( "\n\nICMP packet:\n");
	printIpHeader(buf, size);

	fprintf( "ICMP header:");
	fprintf( "    |-Code          : %d\n", (unsigned int)icmph->code);
	fprintf( "    |-Checksum      : %d\n", ntohs(icmph->checksum));
	/*fprintf( "    |-ID            : %d\n", ntohs(icmph->id)); */
	fprintf( "\n");
	fprintf( "IP header:\n");
	fhexdump( buf, iphdrlen);
	fprintf( "UDP header:\n");
	fhexdump( buf + iphdrlen, sizeof(icmph));
	fprintf( "Data payload:\n");
	fhexdump( buf + iphdrlen + sizeof(icmph), (size - sizeof(icmph) - iph->ihl*4 ));
	fprintf( "\n###############################333333####################");
}

