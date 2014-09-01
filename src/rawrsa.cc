#include "node.h"
#include "nan.h"
#include "node_buffer.h"
#include "node_object_wrap.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "v8.h"

namespace rawrsa {

using namespace node;
using namespace v8;

class Key : public ObjectWrap {
 public:
  static void Init(Handle<Object> target) {
    Local<FunctionTemplate> t = NanNew<FunctionTemplate>(Key::New);

    t->InstanceTemplate()->SetInternalFieldCount(1);
    t->SetClassName(NanNew<String>("Key"));

    NODE_SET_PROTOTYPE_METHOD(t, "size", Key::Size);
    NODE_SET_PROTOTYPE_METHOD(t, "privateDecrypt", Key::Op<kPrivateDecrypt>);
    NODE_SET_PROTOTYPE_METHOD(t, "publicEncrypt", Key::Op<kPublicEncrypt>);

    target->Set(NanNew<String>("Key"), t->GetFunction());

    // Constants
    target->Set(NanNew<String>("RSA_PKCS1_PADDING"),
                NanNew<Int32>(RSA_PKCS1_PADDING));
    target->Set(NanNew<String>("RSA_NO_PADDING"),
                NanNew<Int32>(RSA_NO_PADDING));
    target->Set(NanNew<String>("RSA_PKCS1_OAEP_PADDING"),
                NanNew<Int32>(RSA_PKCS1_OAEP_PADDING));
  }

 protected:
  Key(EVP_PKEY* evp, RSA* rsa) : evp_(evp), rsa_(rsa) {
    if (evp_ != NULL) {
      assert(rsa_ == NULL);
      rsa_ = evp_->pkey.rsa;
    }
  }

  ~Key() {
    if (evp_ != NULL)
      EVP_PKEY_free(evp_);
    else
      RSA_free(rsa_);
    evp_ = NULL;
    rsa_ = NULL;
  }

  static NAN_METHOD(New) {
    NanScope();

    if (args.Length() != 1 || !Buffer::HasInstance(args[0])) {
      return NanThrowError("Invalid arguments length, expected "
                           "new Key(buffer)");
    }

    unsigned char* buf = reinterpret_cast<unsigned char*>(
        Buffer::Data(args[0]));
    int buf_len = Buffer::Length(args[0]);

    RSA* rsa;
    EVP_PKEY* evp = NULL;

    const unsigned char* pbuf;

    pbuf = buf;
    rsa = d2i_RSAPrivateKey(NULL, &pbuf, buf_len);
    if (rsa != NULL)
      goto done;

    pbuf = buf;
    rsa = d2i_RSAPublicKey(NULL, &pbuf, buf_len);
    if (rsa != NULL)
      goto done;

    pbuf = buf;
    rsa = d2i_RSA_PUBKEY(NULL, &pbuf, buf_len);
    if (rsa != NULL)
      goto done;

    {
      BIO* bio = BIO_new_mem_buf(buf, buf_len);
      evp = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
      if (evp == NULL)
        evp = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
      if (evp == NULL) {
        rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
        if (rsa == NULL)
          rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
      }

      BIO_free_all(bio);
    }

 done:
    if (evp == NULL && rsa == NULL)
      return NanThrowError("Failed to read EVP_PKEY/RSA");

    Key* k = new Key(evp, rsa);
    k->Wrap(args.This());

    NanReturnValue(args.This());
  }

  static NAN_METHOD(Size) {
    NanScope();

    Key* k = ObjectWrap::Unwrap<Key>(args.This());
    NanReturnValue(NanNew<Int32>(RSA_size(k->rsa_)));
  }

  enum OpKind {
    kPrivateDecrypt,
    kPublicEncrypt
  };

  template <OpKind K>
  static NAN_METHOD(Op) {
    NanScope();

    if (args.Length() != 3 ||
        !Buffer::HasInstance(args[0]) ||
        !Buffer::HasInstance(args[1]) ||
        !args[2]->IsInt32()) {
      return NanThrowError("Invalid arguments length, expected (out, in, pad)");
    }

    Key* k = ObjectWrap::Unwrap<Key>(args.This());

    unsigned char* to = reinterpret_cast<unsigned char*>(Buffer::Data(args[0]));
    int to_len = Buffer::Length(args[0]);
    if (to_len != RSA_size(k->rsa_))
      return NanThrowError("Invalid output length");

    unsigned char* from = reinterpret_cast<unsigned char*>(
        Buffer::Data(args[1]));
    int from_len = Buffer::Length(args[1]);

    int pad = args[2]->Int32Value();

    int r;
    if (K == kPrivateDecrypt)
      r = RSA_private_decrypt(from_len, from, to, k->rsa_, pad);
    else
      r = RSA_public_encrypt(from_len, from, to, k->rsa_, pad);

    NanReturnValue(NanNew<Int32>(r));
  }

  EVP_PKEY* evp_;
  RSA* rsa_;
};

static void Init(Handle<Object> target) {
  // Init OpenSSL
  OpenSSL_add_all_algorithms();

  Key::Init(target);
}

NODE_MODULE(rawrsa, Init);

}  // namespace rawcipher
