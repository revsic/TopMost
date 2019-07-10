#include <nan.h>

#include "../src/TopMost.hpp"

struct TopMostWrapper : public Nan::ObjectWrap {
    std::unique_ptr<TopMost::MakeTop> obj;

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
    if(!info.IsConstructCall()) {
        return Nan::ThrowError(Nan::New("TopMostWrapper::New - called without new keyword").ToLocalChecked());
    }

    if(info.Length() != 0) {
        return Nan::ThrowError(Nan::New("TopMostWrapper::New - no argument is required").ToLocalChecked());
    }

    TopMostWrapper* vec = new TopMostWrapper();
    vec->Wrap(info.Holder());

    vec->obj = TopMost::MakeTop::CurrentProc(true, false, false);
    info.GetReturnValue().Set(info.Holder());
}

NAN_MODULE_INIT(InitModule) {
    TopMostWrapper::Init(target);
}

NODE_MODULE(topmost, InitModule);
