
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#if HAVE_NET_BPF_H
#ifdef _AIX
/* Prevent bpf.h from redefining the DLT_ values to their IFT_ values. (See
 * similar comment in libpcap/pcap-bpf.c.) */
#undef _AIX
#include <net/bpf.h>
#define _AIX
#else
#include <net/bpf.h>
#endif
#endif
#include "capture.hh"
#include "packet.hh"

#define container_of(ptr, type, member) ({ \
                const typeof( ((type *)0)->member ) *__mptr = (ptr); \
                (type *)( (char *)__mptr - offsetof(type,member) );})



Capture::Capture():
_session(NULL)
{
    memset(&_poll_watcher, 0x00, sizeof(_poll_watcher));
}


Capture::~Capture()
{

}


bool Capture::preparing(const char *dev){

	char errbuf[PCAP_ERRBUF_SIZE] = {NULL};
    if(_session){
        return true;
    }
    #define BUFSIZE 255
	if ((_session = pcap_open_live (dev, BUFSIZE, 0, 0, errbuf)) == NULL) {
		fprintf(stderr, "Could not open device %s: error: %s \n ", dev, errbuf);
        return false;
	}

	if( -1 == pcap_setnonblock(_session, 1, errbuf)){
		fprintf(stderr, "Couldn't set pcap session to nonblock mode :%s\n", pcap_geterr(_session));
		return false;
	}

    return _session != NULL;
}

void Capture::destory(){
    if(_session){
	    pcap_close(_session);
	    _session = NULL;
    }
}

//tcp[tcpflags] & (tcp-syn|tcp-ack) != 0 and src host %s and port 54321
bool Capture::start(const char *target)
{
    if(_session == NULL){
        return false;
    }

	struct pcap_pkthdr header;
	struct bpf_program filter;		
	char filter_exp[256] = {0};
    sprintf(filter_exp, "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) != 0 and src host %s", target);
	//sprintf(filter_exp, "src host %s", target);

	fprintf(stdout, "filter exp: %s \n ", filter_exp);
	if (pcap_compile(_session, &filter, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s \n ", filter_exp, pcap_geterr(_session));
		return false;
	}
	if (pcap_setfilter(_session, &filter) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(_session));
		return false;
	}

    int fd = pcap_get_selectable_fd((pcap_t*)_session);
#ifdef BIOCIMMEDIATE
	if (fd != -1) {
		int immediate = 1;
		if (ioctl(fd, BIOCIMMEDIATE, &immediate) < 0)
            printf("Cannot set BIOCIMMEDIATE on pcap descriptor");
	}
#endif
	int rc = uv_poll_init_socket(uv_default_loop(), &_poll_watcher, (uv_os_sock_t)fd);
	/*
	https://www.codeproject.com/Articles/1267996/%2FArticles%2F1267996%2FFunctional-Programming-in-Cplusplus
	http://www.partow.net/programming/templatecallback/index.html
	http://www.tedfelix.com/software/c++-callbacks.html
	https://embeddedartistry.com/blog/2017/7/10/using-a-c-objects-member-function-with-c-style-callbacks
	*/
	return uv_poll_start(&_poll_watcher, UV_READABLE , [](uv_poll_t* watcher, int status, int events){

        Capture *_capture = (Capture*)container_of(watcher, class Capture, _poll_watcher);

        bool verbose_mode = false;
		struct pcap_pkthdr *pkt_header;
		const unsigned char *packet = NULL;
        
		int rc = pcap_next_ex(_capture->_session, &pkt_header, &packet);
		
		//	sometime we got empty packet which ref to NULL,check it before the program goes crash
		if(packet == NULL){
			return;
		}

        //printf("pkt_header info, caplen:%d, len:%d\r\n", pkt_header->caplen,pkt_header->len);
		
		const struct sniff_tcp *tcp;
		const struct sniff_ip *ip;
		const struct sniff_ethernet *ether;
		struct servent *serv;
		int size_ip;
		int size_tcp;
		ether = (struct sniff_ethernet*) (packet);
		ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);

		size_ip = IP_HL(ip)*4;

		if (size_ip < 20) {
			fprintf (stderr, "Invalid IP header length: %u bytes \n", size_ip);
			return;
		}

		if (ip->ip_p != IPPROTO_TCP) {
			fprintf (stderr, "Returned Packet is not TCP protocol \n");
			return;
		}

		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			fprintf (stderr, " * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}

		/* 
			the actual SYN scanning (heh) : we examine if the SYN flag is on at the receiving packet(port open) 
			原端口号也要进行匹配，否则会抓到其他进程反馈的tcp包

            直接在filter中设置过滤选项

            此处只需要打印出syn+ack状态的tcp包的 目标的ip地址以及端口号即可

		*/
		if ( true /*((tcp->th_flags & 0x02) == TH_SYN) && (tcp->th_flags & 0x10) == TH_ACK*/) {
			fprintf (stdout, "TCP port %d open\n", htons(tcp->th_sport),  htons(tcp->th_win));
			_capture->_ports.push_back(htons(tcp->th_sport));
			//serv = getservbyport ( htons((int)args), "tcp" );
			//fprintf (stdout, "TCP port %d open , possible service: %s\n", args, serv->s_name);
			// RST is sent by kernel automatically
		}
		else if ((tcp->th_flags & 0x04 ) == TH_RST && verbose_mode) {
			//fprintf (stdout, "TCP port %d closed\n", args ); too much info on screen
		}
		else if (verbose_mode) {
			//fprintf (stdout, "Port %d state unknown/filtered \n", args);
		}
	}) >= 0;
}
void Capture::stop()
{
    uv_poll_stop(&_poll_watcher);
	memset(&_poll_watcher, 0x00, sizeof(_poll_watcher));
}
