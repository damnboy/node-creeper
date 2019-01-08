#include "pcap.h"
#include "uv.h"

#include "packet.hh"
#include "capture.hh"
#include <napi.h>

using namespace Napi;

class Scanner: public Napi::ObjectWrap<Scanner>{
public:
	Scanner(const Napi::CallbackInfo &info);
	~Scanner();

	static void exposeClass(Napi::Env& env, Napi::Object& exports){
		Napi::Function constructor = DefineClass(env, "Scanner", {
			InstanceMethod("syn", &Scanner::syn),
		});
		exports.Set("Scanner", constructor);
	}
	
	/*
		单机扫描
		单机指定端口扫描
		多主机扫描
	*/
	// 记录index，分段投递到线程池中执行
	Napi::Value syn(const Napi::CallbackInfo &info);

	bool scanning();
	bool preparing();
	void destory();

	bool complete(){
		bool complete = (_ports.size() == 0);
		return complete;
	}
	
	struct hostent* host_resolve(const char * target);

public:
	int _rate;
	Capture _capture;
	std::vector<int> _ports;
	std::string _src;
	std::string _dest;
	std::string _dev;
};
