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

static void hndlpacket();

static void hndlip();

static void hndltcp();
static void hndludp();
static void hndlicmp();

static char hexchrs[] = "0123456789ABCDEF" ;
static char *argv0;

/* Always current packet raw data. */
static unsigned char *buf;

/* Always current size of all packet. */
static unsigned int size;

/* Always current IP header. */
static struct iphdr *iph;
unsigned short iphlen;


static struct sockaddr_in src, dest;

int
main(int argc, char *argv[]){
	int n1, n2;
	argv0 = argv[0];

	buf = malloc(256*256) ;

	iph = (struct iphdr *)buf ;
	printf("{\"packets\":[");
	while(1){
		/* Read IP header to make further processing. */
		n1 = read(0, buf, sizeof(struct iphdr)) ;
		if(!n1) break ;

		size = iph->tot_len ;
		iphlen = iph->ihl*4 ;

		n2 = read(0, buf+iphlen, size-iphlen) ;
		if(!n2) break ;

		hndlpacket();
	}
	printf("]}");

	return 0 ;
}

char *
c2h(char hex[2], unsigned char c)
{
        hex[0] = hexchrs[c / 16] ;
        hex[1]  = hexchrs[c % 16] ;
        return hex ;
}

void
writehex(char *b, int n)
{
        int i;
        char h[2];

        for( ; n ; --n){
		c2h(h, *b);
                printf("%c%c", h[0], h[1]);
		++b;
        }
}

void
hndlpacket()
{
	printf("{");
	switch(iph->protocol){
	case TcpProto :
		hndltcp();
	break;
	case IcmpProto :
		hndlicmp();
	break;
	/*case IgmpProto :
		hndligmp();
	break;*/
	case UdpProto :
		hndludp();
	break;
	default:
		printf("\"error\":\"unknown protocol\"");
	}
	printf("},");
}

void
hndlip()
{
	memset(&src, 0, sizeof(src));
	src.sin_addr.s_addr = iph->saddr ;

	printf("\"ip\":{");
	printf("\"version\": %d,", (unsigned int)iph->version);
	if(iph->version == 4){
		printf("\"len\":%d,", (unsigned int)iph->ihl);
		printf("\"tos\":%d,", (unsigned int)iph->tos );
		printf("\"id\":%d,", ntohs(iph->id));
		/*printf("\"reserved_zero\":%d,", (unsigned int)iph->ip_reserved_zero);
		printf("\"dont_fragment\":%d,", (unsigned int)iph->ip_dont_fragment);
		printf("\"more_fragment\":%d,", (unsigned int)iph->ip_more_fragment);*/
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

	struct tcphdr *tcph = (struct tcphdr *)(buf + iphlen) ;
	unsigned short int tcphlen = tcph->doff * 4 ;

	hndlip();
	printf(",\"tcp\":{");
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

	printf("},\"payload\":{\"data\":\"");
	writehex(buf + iphlen + tcphlen,
		size - tcphlen - iphlen
	);
	printf("\"}");
}

void
hndludp()
{
	struct udphdr *udph = (struct udphdr *)(buf + iphlen) ;

	hndlip();
	printf(",\"udp\":{");
	printf("\"src\":%d,", ntohs(udph->source));
	printf("\"len\":%d,", ntohs(udph->len));
	printf("\"ck\":%d,", ntohs(udph->check));
	printf("}");
}

void
hndlicmp()
{
	struct icmphdr *icmph = (struct icmphdr *)(buf + iphlen) ;

	hndlip();
	printf(",\"icmp\":{");
	printf("\"code\":%d,", (unsigned int)icmph->code);
	printf("\"ck\":%d,", ntohs(icmph->checksum));
	/*fprintf("\"id\":%d,", ntohs(icmph->id)); */
	writehex(buf + iphlen + sizeof(*icmph), size - sizeof(*icmph) - iphlen);
	printf("}");
}

