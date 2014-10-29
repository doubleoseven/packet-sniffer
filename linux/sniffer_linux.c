/* Simple Raw Sniffer                                                     
* To compile: gcc sniffer.c -o sniffer -lpcap               
*/
#define __USE_BSD
#define __FAVOR_BSD

#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header

#define MAXBYTES2CAPTURE 2048 

struct sockaddr_in source,dest;
FILE *logfile;

void print_ethernet_header(const u_char * packet, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)packet;
    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "  MAC Dst Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
	     eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "  MAC Src Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
	    eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
}

void print_ip_header(const u_char * packet, int Size)
{
    print_ethernet_header(packet, Size);
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(packet  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "  TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "  Src IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(logfile , "  Dst IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}
void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    print_ip_header(Buffer , Size);
    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "  Src Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "  Dst Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "  Seq #    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "  Ack # : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "  Ack Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "\n");
    fprintf(logfile , "\n------------------------------");
}
void print_icmp_packet(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
    print_ip_header(Buffer , Size);
    fprintf(logfile , "\n");
    fprintf(logfile , "\n------------------------------");
}
void print_udp_packet(const u_char *Buffer , int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    print_ip_header(Buffer,Size);
    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   Src Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   Dst Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "\n------------------------------");
}
/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in  */
/* hexadecimal.                                                                */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){ 
    int size = pkthdr->len;
    int i=0, *counter = (int *)arg; 
    printf("Received Packet Size: %d\n", size); 
    fprintf(logfile, "Received Packet Size: %d\n", size);  
    //printf("\n"); 
    fprintf(logfile, "\n"); 
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    if(iph->protocol == 6)//tcp
	print_tcp_packet(packet, size);
    else if(iph->protocol == 1)//or icmp
	print_icmp_packet(packet, size);
    else if(iph->protocol == 17)//or udp
	print_udp_packet(packet , size);
    fprintf(logfile, "\n"); 
    return; 
} 

/* main(): Main function. Opens network interface and calls pcap_loop() */
int main(int argc, char *argv[] ){ 
    int i=0, count=0; 
    /* Pointer to the device that will be sniffed. */
    pcap_t *descr = NULL; 
    /* for setting up the filter */
    struct bpf_program filter;        /* Place to store the BPF filter program  */ 
    bpf_u_int32 netaddr=0, mask=0;    /* To Store network address and netmask   */ 

    struct pcap_pkthdr pkthdr;        /* Packet information (timestamp,size...) */ 
    int filter_flag = 0;   
    int protocol_flag = 0;
    const char *filename;
    const char *protocol_name;
    char  *filter_exp = malloc(1000);
    char errbuf[PCAP_ERRBUF_SIZE], *device=NULL; 
    /* Buffer to store error msg incase something went wrong */
    memset(errbuf,0,PCAP_ERRBUF_SIZE); 
    if( argc < 2){  /* If user supplied interface name, use it. */
    //read the logfile name and the flags passed by the user
	exit(1);
    }
    else{
	for(i=1; i < argc; i++){
	    if((strcmp(argv[i], "--protocol")) == 0)
	    {
		protocol_name = argv[i+1];
		if( (strcmp(protocol_name, "http") ==  0)| (strcmp(protocol_name, "https") ==  0)
		| (strcmp(protocol_name, "ssh") ==  0)| (strcmp(protocol_name, "smtp") ==  0)
		| (strcmp(protocol_name, "telnet") ==  0)| (strcmp(protocol_name, "icmp") ==  0) )
			    protocol_flag = 1;
	    }
	    else if((strcmp(argv[i], "--bpf")==0)){
		int j;
		j = i;
		int off = 0;
		while ((strcmp(argv[j+1], "--log"))!=0){
		    j++;
		    off +=sprintf(filter_exp+off, argv[j]);
		    off +=sprintf(filter_exp+off, " ");
		}
		printf("bpf: %s\n",filter_exp);
		filter_flag = 1;
	    }
	    else if((strcmp(argv[i], "--log"))==0)
		filename = argv[i+1];
	}
    }

    /* Get the name of the first device suitable for capture */ 
    if ( (device = pcap_lookupdev(errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
     } 
     printf("Opening device %s\n", device); 
    /* Open device in promiscuous mode */ 
    if ( (descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL){
	fprintf(stderr, "ERROR: %s\n", errbuf);
	exit(1);
    }  

    /* Look up info from the capture device. */
    pcap_lookupnet( argv[1] , &netaddr, &mask, errbuf);
    /* Filter Info */
    if(filter_flag){
	pcap_compile(descr, &filter, filter_exp, 1, mask);
	pcap_setfilter(descr,&filter);
    }
    else if(protocol_flag){
	/* http by default uses TCP port 80 or 8080 */
	if((strcmp(protocol_name, "http"))==0)
	    filter_exp = "tcp and (dst port 80 or dst port 8080)";
	/* SMTP by default uses TCP port 25 */
	else if((strcmp(protocol_name, "https"))==0)
	    filter_exp = "tcp and (dst port 443)";
	/* ssh by default uses TCP port 22 */
	else if((strcmp(protocol_name, "ssh"))==0)
	    filter_exp = "(dst port 22)";
	else if((strcmp(protocol_name, "telnet"))==0)
	    filter_exp = "(dst port 23)";
	else if((strcmp(protocol_name, "smtp"))==0)
	    filter_exp = "(dst port 25)";
	/* SMTP by default uses TCP port 25 */
	else if((strcmp(protocol_name, "icmp"))==0)
	    filter_exp = "icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply";
	pcap_compile(descr, &filter, filter_exp, 1, mask);
    	pcap_setfilter(descr,&filter);
    }

    logfile=fopen(filename,"a");//take the name of the file from the user
    if(logfile==NULL)
	printf("Unable to create file.");

    /* Loop forever & call processPacket() for every received packet*/ 
    if ( pcap_loop(descr, -1, processPacket, (u_char *)&count) == -1){
	fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
	exit(1);
    }  

    return 0; 
} 

/* EOF*/
