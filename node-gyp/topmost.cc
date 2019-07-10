#include <nan.h>

#include "../src/TopMost.hpp"

struct TopMostWrapper : public Nan::ObjectWrap {
    std::unique_ptr<TopMost::MakeTop> obj;

    ~TopMostWrapper() {
        obj.reset();
    }

    static NAN_MODULE_INIT(Init);
    static NAN_METHOD(New);

    static Nan::Persistent<v8::FunctionTemplate> constructor;    
};

Nan::Persistent<v8::FunctionTemplate> TopMostWrapper::constructor;

NAN_MODULE_INIT(TopMostWrapper::Init) {
    v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(TopMostWrapper::New);
    constructor.Reset(ctor);

    ctor->InstanceTemplate()->SetInternalFieldCount(1);
    ctor->SetClassName(Nan::New("TopMostWrapper").ToLocalChecked());

    target->Set(Nan::New("TopMostWrapper").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(TopMostWrapper::New) {
    if (!info.IsConstructCall()) {
        return Nan::ThrowError(Nan::New("TopMostWrapper::New - called without new keyword").ToLocalChecked());
    }

    if (!(info.Length() == 0
        || (info.Length() == 1 && info[0]->IsBoolean())
        || (info.Length() == 2 && info[0]->IsBoolean() && info[1]->IsNumber())))
    {
        return Nan::ThrowError(Nan::New("TopMostWrapper::New - expected arguments: () or (log) or (log, pid)").ToLocalChecked());
    }

    TopMostWrapper* vec = new TopMostWrapper();
    vec->Wrap(info.Holder());

    bool log = info.Length() > 0 ? info[0]->BooleanValue() : false;
    DWORD dwPid = info.Length() > 1 ? info[1]->NumberValue() : GetCurrentProcessId();

    vec->obj = std::make_unique<TopMost::MakeTop>(dwPid, true, false, log);
    info.GetReturnValue().Set(info.Holder());
}

NAN_MODULE_INIT(InitModule) {
    TopMostWrapper::Init(target);
}

NODE_MODULE(topmost, InitModule);
