#include "napi.h"

class PcapDevice: public Napi::ObjectWrap<PcapDevice>{

public:
	PcapDevice(const Napi::CallbackInfo &info);

	static void exposeClass(Napi::Env& env, Napi::Object& exports){
		Napi::Function constructor = DefineClass(env, "PcapDevice", {
			InstanceMethod("listDevice", &PcapDevice::listDevice),
		});
		exports.Set("PcapDevice", constructor);
	}
	
	Napi::Value listDevice(const Napi::CallbackInfo &info);

};