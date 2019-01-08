#include "pcap.h"
#include "uv.h"
#include <napi.h>

using namespace Napi;


class Capture{
public:
	Capture();
	~Capture();

	bool preparing(const char *dev);
    bool start(const char *target);
    void stop();
	void destory();

public:
	uv_poll_t _poll_watcher;
	pcap_t *_session;
	std::vector<int> _ports;
};

