#pragma once

#include <napi.h>

class NodeCreeper : public Napi::ObjectWrap<NodeCreeper>
{
public:
    NodeCreeper(const Napi::CallbackInfo&);
    Napi::Value Greet(const Napi::CallbackInfo&);

    static Napi::Function GetClass(Napi::Env);

private:
    std::string _greeterName;
};
