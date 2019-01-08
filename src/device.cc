#include "pcap.h"
#include "device.hh"
#include <arpa/inet.h>
#include "util.hh"

//void PcapDevice::exposeClass(Napi::Env& env, Napi::Object& exports){
//	
//}

PcapDevice::PcapDevice(const Napi::CallbackInfo &info)
:ObjectWrap(info){

}

Napi::Value PcapDevice::listDevice(const Napi::CallbackInfo& i){

	CbInfo info(i);

	info.validate({napi_valuetype::napi_function});

	Napi::Function cb = info.extractFunction(0);

	pcap_if_t *alldev;
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((pcap_findalldevs(&alldev, errbuf)) == -1) {
		fprintf (stderr, "%s\n", errbuf);
		return info.Env().Undefined();
	}

	Napi::Object interfaces = Napi::Object::New(info.Env());
	struct sockaddr_in * ip(NULL);
	while(alldev){
		//printf("dev:%s\r\n", alldev->name);
		Napi::Array addresses = Napi::Array::New(info.Env());
		
		struct pcap_addr *address = alldev->addresses;
		int cnt = 0;
		while (address) {
			if (address->addr) {
				ip = (struct sockaddr_in *) address->addr;
				addresses.Set(cnt++, Napi::String::New(info.Env(), inet_ntoa(ip->sin_addr)));
				//fprintf (stdout, "Local IP: %s \n", inet_ntoa(ip->sin_addr));
			}
			address = address->next;
		}

		interfaces.Set(alldev->name, addresses);

		alldev = alldev->next;
	}

	Napi::Value ret = cb.Call({interfaces});
	return ret;
}
