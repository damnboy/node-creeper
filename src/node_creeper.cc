#include <unistd.h>
#include <thread>
#include <iostream>
#include "node_creeper.h"
#include "scanner.hh"
#include "device.hh"
using namespace Napi;



Napi::Object InitAll(Napi::Env env, Napi::Object exports){
	PcapDevice::exposeClass(env, exports);
	Scanner::exposeClass(env, exports);
	return exports;
}

NODE_API_MODULE(addon, InitAll)
