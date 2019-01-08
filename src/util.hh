#include <napi.h>

class CbInfo{

public:
  CbInfo(const Napi::CallbackInfo& info):
  _info(info){

  }

  ~CbInfo(){

  }

  bool validate(std::vector<napi_valuetype> types){
    if(_info.Length() != types.size()){
      throw Napi::TypeError::New(_info.Env(), "no enough parameters");
    }

    bool valid = true;
    for(int i = 0; i<types.size(); i++){
      bool temp = (types[i] == _info[i].Type());
      if(!temp){
        char buffer [128] = {0};
        char *t[] = {
          "napi_undefined",
          "napi_null",
          "napi_boolean",
          "napi_number",
          "napi_string",
          "napi_symbol",
          "napi_object",
          "napi_function",
          "napi_external",
        };
        sprintf (buffer, "the %d parameter must be %s", i+1, t[types[i]]);
        throw Napi::TypeError::New(_info.Env(), buffer);
      }
      valid = valid && temp;
    }

    return valid;
  }

  std::string extractString(int index){
    return _info[index].As<Napi::String>().Utf8Value();
  }

  Napi::Object extractObject(int index){
    return _info[index].As<Napi::Object>();
  }

  int extractInt(int index){
    return _info[index].As<Napi::Number>().Int32Value();
  }

//cb.Call(env.Global(), { Napi::String::New(env, "hello world") });
  Napi::Function extractFunction(int index){
    return _info[index].As<Napi::Function>();
  }

  Napi::Env Env(){
    return _info.Env();
  } 
  
private:
  const Napi::CallbackInfo& _info;
};
