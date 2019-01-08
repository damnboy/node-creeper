
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
#include <thread>
#include <iostream>
#include "scanner.hh"
#include "util.hh"

using namespace Napi;


class PiWorker : public Napi::AsyncWorker {
 public:
  PiWorker(Scanner *pScanner, Napi::Function _continue)
    : Napi::AsyncWorker(_continue)
	{
		_pScanner = pScanner;
	}
  ~PiWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access JS engine data structure
  // here, so everything we need for input and output
  // should go on `this`.
  void Execute () {
		//std::thread::id this_id = std::this_thread::get_id();
		//std::cout << "[" << this_id << "]  thread PiWorker \n";
	  	//while(!_pScanner->complete()){
		 	_pScanner->scanning();
			int delay = 1;
			if(_pScanner->complete()){
				delay = 5;
			}
		  	sleep(delay); //发送间隔
	 	//}
	 	//sleep(5); //5秒超时，等待主线程pcap抓包执行完毕
  }

  // Executed when the async work is complete
  // this function will be run inside the main event loop
  // so it is safe to use JS engine data again
  void OnOK() {
	//std::thread::id this_id = std::this_thread::get_id();
	//std::cout << "[" << this_id << "]  thread PiWorker Finished!!! \n";
	if(_pScanner->complete()){
		_pScanner->destory();
		Napi::HandleScope scope(Env());
		Napi::Array array = Napi::Array::New(Env());
		for(int i=0; i<_pScanner->_capture._ports.size(); i++){
			array.Set(i, Napi::Number::New(Env(), _pScanner->_capture._ports[i]));
		}
		Callback().Call({array});
	}
	else{
		Reference<Napi::Function> &ref = Callback();
		PiWorker *p = new PiWorker(_pScanner, ref.Value());
  		p->Queue();
	}
	
  }

  Scanner *_pScanner;
};


Scanner::Scanner(const Napi::CallbackInfo &info):
ObjectWrap(info),
_rate(200)
{
}

Scanner::~Scanner()
{

}

Napi::Value Scanner::syn(const Napi::CallbackInfo &i){

	CbInfo info(i);

	info.validate({
		napi_valuetype::napi_object, 
		napi_valuetype::napi_function
	});
	
	Napi::Object options = info.extractObject(0);
	// js context下的变量，必须缓存进native context中，直接引用utf8value.c_str，其值在运行时会不断变化
	_dest = options.Get("target").As<Napi::String>().Utf8Value();
	_src = options.Get("address").As<Napi::String>().Utf8Value();
	_dev = options.Get("dev").As<Napi::String>().Utf8Value();

	if(!options.Get("rate").As<Napi::Number>().IsUndefined()){
		_rate = options.Get("rate").As<Napi::Number>().Int32Value();
	}

	Napi::Array ports = options.Get("ports").As<Napi::Array>();
	if(ports.IsUndefined() || ports.Length() == 0){
		for(int i=65535; i>=1; i--){
			this->_ports.push_back(i);
		}
	}
	else{
		for(int i=0; i<ports.Length(); i++){
			this->_ports.push_back(ports.Get(i).As<Napi::Number>().Int32Value());
		}
	}

	Napi::Function cb = info.extractFunction(1);

	this->preparing();

  	PiWorker *p = new PiWorker(this, cb);
  	p->Queue();
}


bool Scanner::preparing()
{
	//解析目标域名到 target_addr
	struct servent *serv;
	struct hostent *hostname;
	hostname = (struct hostent *)host_resolve(_dest.c_str());
	char **addr = hostname->h_addr_list;
	char temp[16] = {0};
	strncpy((char*)temp, inet_ntoa(*(struct in_addr *)*addr), 16);
	_dest = temp;

	if(_capture.preparing(_dev.c_str())){
		_capture.start(_dest.c_str());
	}
}


void Scanner::destory(){
	this->_capture.stop();
	this->_capture.destory();
}


// 记录index，分段投递到线程池中执行
bool Scanner::scanning()
{
	//printf("%d", _port);
	int sockfd = 0;
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		perror("sock:");
		return false;
	}
		
	int one = 1;
	const int *val = &one;
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
		fprintf(stderr, "Warning: Cannot set HDRINCL for port %d\n", 0);

	//int low = _port;
	//int high = (_port += 1024);
	//printf("low:%d, high:%d\r\n", low, high);
	int cnt = 0;
	while(_ports.size() > 0 && cnt++ < _rate){
		int port = _ports.back();
		_ports.pop_back();

		int len = sizeof (struct sniff_ip) + sizeof (struct sniff_tcp);
		TCPPacket packet;
		packet.build(_src.c_str(), _dest.c_str(), port);
		const char * datagram = packet._buffer;//this->_packets.packet(_target, port, _source);
		
		struct sockaddr_in sin_target;
		sin_target.sin_family = AF_INET;
		inet_pton(AF_INET, _dest.c_str(), &sin_target.sin_addr);
		if (sendto(sockfd, datagram, len, 0, (struct sockaddr *)&sin_target, sizeof(sin_target)) < 0) {
			fprintf(stderr, "Error sending datagram for port %d\n", port);
		}
	}
	return true;
}

struct hostent* Scanner::host_resolve(const char * target) 
{
	struct hostent *hostname;
	
	if (!(hostname = gethostbyname(target))) {
		fprintf (stderr, "Host name resolution failed for %s \n"
			"Try using the nslookup prog to find the IP address\n", target);
		return NULL;
	}
	if (true) {
		fprintf(stdout, "Host Resolution results:\n"
				"Name: %s\n"
				"Aliases:", hostname->h_name);
		char **alias = hostname->h_aliases;
		while(*alias) {
			fprintf(stdout, "%s ", *alias);
			alias++;
		}	
		char **addrs = hostname->h_addr_list;
		fprintf(stdout, "\nIP address/es:\n");
		while(*addrs) {
			fprintf(stdout, " %s ", inet_ntoa(*(struct in_addr *)*addrs));
			addrs++;
		}
		printf("\n");
	}
	return hostname;
}
