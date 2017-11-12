

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <time.h>
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
char *string = NULL;

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;


	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void packet_details(char buf[], const struct pcap_pkthdr * header,const struct sniff_ethernet *ethernet, const struct sniff_ip *ip, const struct sniff_tcp *tcp, const struct sniff_udp *udp,const char* payload,int size_payload){
				

				/*Printing packet details*/
				printf("\n%s ",buf);
				printf("%02x:%02x:%02x:%02x:%02x:%02x -> ",
				  (u_char) ethernet->ether_shost[0],
				  (u_char) ethernet->ether_shost[1],
				  (u_char) ethernet->ether_shost[2],
				  (u_char) ethernet->ether_shost[3],
				  (u_char) ethernet->ether_shost[4],
				  (u_char) ethernet->ether_shost[5]);

				printf("%02x:%02x:%02x:%02x:%02x:%02x ",
				  (u_char) ethernet->ether_dhost[0],
				  (u_char) ethernet->ether_dhost[1],
				  (u_char) ethernet->ether_dhost[2],
				  (u_char) ethernet->ether_dhost[3],
				  (u_char) ethernet->ether_dhost[4],
				  (u_char) ethernet->ether_dhost[5]);
				
				
				switch(ntohs(ethernet->ether_type)){
					case 0x800: printf("type 0x%x(IPv4) ",ntohs(ethernet->ether_type));
								break;
					case 0x806: printf("type 0x%x(ARP) ",ntohs(ethernet->ether_type));
								break;
					case 0x86DD: printf("type 0x%x(IPv6) ",ntohs(ethernet->ether_type));
								break;
					case 0x8035: printf("type 0x%x(RARP) ",ntohs(ethernet->ether_type));
								break;
					default : printf("type 0x%x(Other) ",ntohs(ethernet->ether_type));
								break;
				}
				printf("len %d\n",header->len);
				printf("%s:", inet_ntoa(ip->ip_src));
				if((ip->ip_p)==IPPROTO_TCP){
					printf("%d -> ", ntohs(tcp->th_sport));
				}
				else{
					printf("%d -> ", ntohs(udp->uh_sport));
				}
				printf("%s:", inet_ntoa(ip->ip_dst));
				if((ip->ip_p)==IPPROTO_TCP){
					printf("%d -> ", ntohs(tcp->th_dport));
				}
				else{
					printf("%d -> ", ntohs(udp->uh_dport));
				}
				switch(ip->ip_p) {
					case IPPROTO_TCP:
						printf("TCP ");
						break;
					case IPPROTO_UDP:
						printf("UDP ");
						break;
					case IPPROTO_ICMP:
						printf("ICMP ");
						break;
					case IPPROTO_IP:
						printf("IP ");
						break;
					default:
						printf("unknown ");
						break;
				}
				printf("\n");

				/*printing payload */
				print_payload(payload, size_payload);
}


void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	static int count = 1;                   /* packet counter */
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;  			/* The UDP header */
	const char *payload;      

	/* printing date and time (help from stackoverflow)*/
	//struct timeval tv;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64]; 			
	//tv=(struct timeval)(header->ts);         
	nowtime = header->ts.tv_sec;  
	nowtm = localtime(&nowtime);  
	strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm); 
	snprintf(buf, sizeof(buf), "%s.%06ld", tmbuf, header->ts.tv_usec);
	int size_ip;
	int size_header;
	int size_payload;
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("* Invalid IP header length: %u bytes\n", size_ip);
		//return;
	}

	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	/* calculating TCP header length*/
	if(ip->ip_p==IPPROTO_TCP){
		size_header = TH_OFF(tcp)*4;
		if (size_header < 20) {
		//printf("* Invalid TCP header length: %u bytes\n", size_header);
		//return;
		}
	}
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	/* setting UDP header length as 8*/
	if(ip->ip_p==IPPROTO_UDP){
		size_header=8;

	}

	/* define/compute payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_header);
	
	
	
	/* compute payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_header);
	char *ch;
	int i;
	
	/*checking if -s arg is set and subsequently handling it*/
	if(string!=NULL){
		if (size_payload > 0) {
			char newpayload[10000];
			int j=0;
			for(i = 0; i < size_payload; i++) {
				if (isprint(payload[i])){
					newpayload[j]=payload[i];
					j++;
				}
			}
			if(strstr(newpayload,string)!=NULL){
				packet_details(buf,header,ethernet,ip,tcp,udp, payload, size_payload);
					
			}
		}
	}

	/* if there is no -s arg set */
	else{		
		packet_details(buf,header,ethernet,ip,tcp,udp, payload, size_payload);

	}

return;
}

int main(int argc, char **argv)
{
	int c;
	int index;
	char *dev = NULL;	/* capture device name */
	int flag=0;
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle = NULL;				/* packet capture handle */

	char filter_exp[100]="";	/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 1;		/* number of packets to capture */
	char  *file_name=NULL;

	//print_app_banner();

	/* handling -s, -i, -r args and BPF filer */
	while((c=getopt_long(argc,argv,"i:r:s:"))!=-1){
		//printf("inside while\n");
		switch(c){
			case 'i':
			dev = optarg;
	 		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	 		flag=1;
			break;
			
			case 'r':
			file_name = optarg;
			handle= pcap_open_offline(file_name,errbuf);
			flag=1;
			break;
			
			case 's':
			string=optarg;
			break;

			case '?':
	        if (optopt == 'r' || optopt == 's'|| optopt=='i')
	          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	        
	        else if (isprint (optopt))
	          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
	        else
	          fprintf (stderr,
	                   "Unknown option character `\\x%x'.\n",
	                   optopt);
	        return 1;
	        break;

			default: break;
		}


	}
	/*handling BPF filer */
	for (index = optind; index < argc; index++){
    	strcat(filter_exp,argv[index]);
    	strcat(filter_exp," ");	
	}

	/* if -i and -s are not set, use the default interface */
	if(flag==0){
		if(dev==NULL){
	    	dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
			exit(EXIT_FAILURE);
		}
	    	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
		}
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
	}

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0,net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);
	//printf("filter exp:%s",filter_exp);
	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
