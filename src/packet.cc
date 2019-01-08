#include "packet.hh"
#include <string.h>
#include <arpa/inet.h>

PacketGenerator::PacketGenerator():
_sport(9876)
{

}
PacketGenerator::~PacketGenerator(){

}
char *PacketGenerator::packet(const char *target, int port, const char *source){
	memset(_datagram, 0, 4096);                  /* zero out the buffer */
	
	struct sockaddr_in sin_source;
	inet_aton(source, &sin_source.sin_addr); //一个字符串IP地址转换为一个32位的网络序列IP地址

	struct sockaddr_in sin_target;
	sin_target.sin_family = AF_INET;
	inet_pton(AF_INET, target, &sin_target.sin_addr);//

	struct sniff_ip *iph = (struct sniff_ip *)_datagram;
	/* tcp header begins right after the end of the ip header */ 
	/* can it work in reverse ? Of course not */
	struct sniff_tcp *tcph = (struct sniff_tcp *)(_datagram + sizeof(struct sniff_ip));
	for (int i = port; i <= port; i++) {
				
		iph->ip_vhl = 0x45;                          /* version=4,header_length=5 (no data) */
		iph->ip_tos = 0;                             /* type of service -not needed */
		iph->ip_len = sizeof (struct sniff_ip) + sizeof (struct sniff_tcp);    /* no payload */
		iph->ip_id = htons(12830);                   /* simple id */
		iph->ip_off = 0;                             /* no fragmentation */
		iph->ip_ttl = 64;                           /* time to live - set max value */
		iph->ip_p = IPPROTO_TCP;                     /* 6 as a value - see /etc/protocols/ */
		iph->ip_src.s_addr = sin_source.sin_addr.s_addr;   /*local device IP */
		iph->ip_dst.s_addr = sin_target.sin_addr.s_addr;    /* dest addr */
		iph->ip_sum = 				     /* no need for ip sum actually */
		checksum( (unsigned short *)iph,
				sizeof(struct sniff_ip));
		tcph->th_sport = htons(this->_sport);                /* arbitrary port */
		tcph->th_dport = htons(i);                   /* scanned dest port */
		tcph->th_seq = 0;//random();                     /* the random SYN sequence */
		tcph->th_ack = 0;                            /* no ACK needed */
		tcph->th_offx2 = 0x50;                       /* 50h (5 offset) ( 8 0s reserverd )*/
		tcph->th_flags = TH_SYN;                     /* initial connection request */
		tcph->th_win = htons(32768);                   /* maximum allowed window size */
		tcph->th_sum = 0;                            /* will compute later */
		tcph->th_urp = 0;                            /* no urgent pointer */
		/* pseudo header for tcp checksum */
		struct pseudo_hdr *phdr = (struct pseudo_hdr *) (_datagram +
				sizeof(struct sniff_ip) + sizeof(struct sniff_tcp));
		phdr->src = iph->ip_src.s_addr;
		phdr->dst = iph->ip_dst.s_addr;
		phdr->mbz = 0;
		phdr->proto = IPPROTO_TCP;
		phdr->len = ntohs(0x14);       /* in bytes the tcp segment length */
		/*- WhyTF is it network byte saved by default ????*/
		tcph->th_sum = htons(checksum((unsigned short *)tcph,
					sizeof(struct pseudo_hdr)+
					sizeof(struct sniff_tcp)));
	}
	return _datagram;
}
uint16_t PacketGenerator::checksum (uint16_t *addr, int len) {   /*  compute TCP header checksum */
	/*  with the usual algorithm a bit changed */
	/*  for byte ordering problem resolving */
	/*  see RFC 1071 for more info */
	/* Compute Internet Checksum for "count" bytes
	*         beginning at location "addr".
	*/
	/*register*/ long sum = 0;
	int count = len;
	uint16_t temp;
	while (count > 1)  {
		temp = htons(*addr++);   // in this line:added -> htons
		sum += temp;
		count -= 2;
	}
	/*  Add left-over byte, if any */
	if(count > 0)
		sum += *(unsigned char *)addr;
	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	uint16_t checksum = ~sum;
	return checksum;
}



IPPacket::IPPacket(){

}

IPPacket::~IPPacket(){

}

u_short IPPacket::checksum (uint16_t *addr, int len) {   /*  compute TCP header checksum */
	/*  with the usual algorithm a bit changed */
	/*  for byte ordering problem resolving */
	/*  see RFC 1071 for more info */
	/* Compute Internet Checksum for "count" bytes
	*         beginning at location "addr".
	*/
	/*register*/ long sum = 0;
	int count = len;
	uint16_t temp;
	while (count > 1)  {
		temp = htons(*addr++);   // in this line:added -> htons
		sum += temp;
		count -= 2;
	}
	/*  Add left-over byte, if any */
	if(count > 0)
		sum += *(unsigned char *)addr;
	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	uint16_t checksum = ~sum;
	return checksum;
}

char *IPPacket::build(const char *sip, const char *dip, int dport, int sport){
	memset(_buffer, 0, 4096);   
	
	struct sniff_ip *iph = (struct sniff_ip *)_buffer;
	iph->ip_vhl = 0x45;                          /* version=4,header_length=5 (no data) */
	iph->ip_tos = 0;                             /* type of service -not needed */
	iph->ip_len = sizeof (struct sniff_ip) + sizeof (struct sniff_tcp);    /* no payload */
	iph->ip_id = htons(12830);                   /* simple id */
	iph->ip_off = 0;                             /* no fragmentation */
	iph->ip_ttl = 64;                           /* time to live - set max value */
	iph->ip_p = IPPROTO_TCP;                     /* 6 as a value - see /etc/protocols/ */

	struct sockaddr_in sin_source;
	inet_aton(sip, &sin_source.sin_addr); //一个字符串IP地址转换为一个32位的网络序列IP地址
	iph->ip_src.s_addr = sin_source.sin_addr.s_addr;   /*local device IP */

	struct sockaddr_in sin_target;
	sin_target.sin_family = AF_INET;
	inet_pton(AF_INET, dip, &sin_target.sin_addr);//
	iph->ip_dst.s_addr = sin_target.sin_addr.s_addr;    /* dest addr */
	iph->ip_sum = 				     /* no need for ip sum actually */
	checksum( (unsigned short *)iph,
				sizeof(struct sniff_ip));

	return (_buffer + sizeof(struct sniff_ip));
}


TCPPacket::TCPPacket(){

}

TCPPacket::~TCPPacket(){

}

u_short TCPPacket::tcpChecksum()
{
	struct sniff_tcp *tcph = (struct sniff_tcp *)(_buffer + sizeof(struct sniff_ip));
	/* pseudo header for tcp checksum */	
	struct pseudo_hdr *phdr = (struct pseudo_hdr *) (_buffer +
			sizeof(struct sniff_ip) + sizeof(struct sniff_tcp));
	phdr->src = ((struct sniff_ip *)_buffer)->ip_src.s_addr;
	phdr->dst = ((struct sniff_ip *)_buffer)->ip_dst.s_addr;
	phdr->mbz = 0;
	phdr->proto = IPPROTO_TCP;
	phdr->len = ntohs(0x14);       /* in bytes the tcp segment length */
	/*- WhyTF is it network byte saved by default ????*/
	return checksum((unsigned short *)tcph,
					sizeof(struct pseudo_hdr)+
					sizeof(struct sniff_tcp));
}

char *TCPPacket::build(const char *sip, const char *dip, int dport, int sport){
	/*
		IPPacket::build
		TCPPacket::build
	*/
	struct sniff_ip *iph = (struct sniff_ip *)_buffer;
	struct sniff_tcp *tcph = (struct sniff_tcp *)(IPPacket::build(sip, dip, dport, sport));
	tcph->th_sport = htons(sport);                /* arbitrary port */
	tcph->th_dport = htons(dport);                   /* scanned dest port */
	tcph->th_seq = 0;//random();                     /* the random SYN sequence */
	tcph->th_ack = 0;                            /* no ACK needed */
	tcph->th_offx2 = 0x50;                       /* 50h (5 offset) ( 8 0s reserverd )*/
	tcph->th_flags = TH_SYN;                     /* initial connection request */
	tcph->th_win = htons(32768);                   /* maximum allowed window size */
	tcph->th_sum = 0;                            /* will compute later */
	tcph->th_urp = 0;                            /* no urgent pointer */
	tcph->th_sum = htons(this->tcpChecksum());

	return (_buffer + sizeof(struct sniff_ip) + sizeof(struct sniff_tcp));
}