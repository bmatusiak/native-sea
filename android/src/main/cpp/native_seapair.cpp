// native_seapair.cpp
#include <jni.h>
#include <string>
#include <vector>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

static std::string toStdString(JNIEnv* env, jstring s) {
  if (s == nullptr) return std::string();
  const char* utf = env->GetStringUTFChars(s, nullptr);
  std::string out(utf);
  env->ReleaseStringUTFChars(s, utf);
  return out;
}

static std::vector<unsigned char> base64UrlDecode(const std::string& in) {
  std::string s = in;
  for (char &c : s) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  size_t mod = s.size() % 4;
  if (mod) s.append(4 - mod, '=');

  BIO* b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO* bmem = BIO_new_mem_buf(s.data(), (int)s.size());
  bmem = BIO_push(b64, bmem);

  std::vector<unsigned char> out(s.size());
  int decoded = BIO_read(bmem, out.data(), (int)out.size());
  BIO_free_all(bmem);
  if (decoded <= 0) return {};
  out.resize(decoded);
  return out;
}

static std::string base64UrlEncodeNoPad(const unsigned char* data, int len) {
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO* bmem = BIO_new(BIO_s_mem());
  BIO* bio = BIO_push(b64, bmem);
  BIO_write(bio, data, len);
  BIO_flush(bio);
  BUF_MEM* bptr = nullptr;
  BIO_get_mem_ptr(bio, &bptr);
  std::string out(bptr->data, bptr->length);
  BIO_free_all(bio);
  for (char &c : out) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
  while (!out.empty() && out.back() == '=') out.pop_back();
  return out;
}

static void throwRuntimeException(JNIEnv* env, const char* msg) {
  jclass ex = env->FindClass("java/lang/RuntimeException");
  if (ex) env->ThrowNew(ex, msg);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_expo_modules_nativesea_SEAPair_nativePublicFromPrivate(JNIEnv* env, jclass /*cls*/, jstring jpriv) {
  std::string privB64 = toStdString(env, jpriv);
  if (privB64.empty()) {
    throwRuntimeException(env, "input private key is empty");
    return nullptr;
  }

  auto privBytes = base64UrlDecode(privB64);
  if (privBytes.empty()) {
    throwRuntimeException(env, "failed to decode base64 private key");
    return nullptr;
  }

  BIGNUM* priv_bn = BN_bin2bn(privBytes.data(), (int)privBytes.size(), nullptr);
  if (!priv_bn) {
    throwRuntimeException(env, "BN_bin2bn failed");
    return nullptr;
  }

  int nid = NID_X9_62_prime256v1; // secp256r1
  EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
  if (!group) {
    BN_free(priv_bn);
    throwRuntimeException(env, "EC_GROUP_new_by_curve_name failed");
    return nullptr;
  }

  BN_CTX* ctx = BN_CTX_new();
  EC_POINT* pub = EC_POINT_new(group);
  if (!pub || !ctx) {
    EC_POINT_free(pub);
    EC_GROUP_free(group);
    BN_free(priv_bn);
    BN_CTX_free(ctx);
    throwRuntimeException(env, "allocations failed");
    return nullptr;
  }

  if (1 != EC_POINT_mul(group, pub, priv_bn, nullptr, nullptr, ctx)) {
    EC_POINT_free(pub);
    EC_GROUP_free(group);
    BN_free(priv_bn);
    BN_CTX_free(ctx);
    throwRuntimeException(env, "EC_POINT_mul failed");
    return nullptr;
  }

  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();
  if (!x || !y) {
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (pub) EC_POINT_free(pub);
    if (group) EC_GROUP_free(group);
    if (priv_bn) BN_free(priv_bn);
    if (ctx) BN_CTX_free(ctx);
    throwRuntimeException(env, "BN allocation failed");
    return nullptr;
  }

  /* Use the modern API when available to avoid deprecated symbol warnings on OpenSSL 3.x */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (1 != EC_POINT_get_affine_coordinates(group, pub, x, y, ctx)) {
#else
  if (1 != EC_POINT_get_affine_coordinates_GFp(group, pub, x, y, ctx)) {
#endif
    BN_free(x); BN_free(y);
    if (pub) EC_POINT_free(pub);
    if (group) EC_GROUP_free(group);
    if (priv_bn) BN_free(priv_bn);
    if (ctx) BN_CTX_free(ctx);
    throwRuntimeException(env, "EC_POINT_get_affine_coordinates failed");
    return nullptr;
  }

  // Ensure coordinates are encoded to fixed byte length (field size) with leading zeros if necessary
  int field_bits = EC_GROUP_get_degree(group);
  int field_bytes = (field_bits + 7) / 8;

  int xlen = BN_num_bytes(x);
  int ylen = BN_num_bytes(y);
  std::vector<unsigned char> xb(field_bytes, 0);
  std::vector<unsigned char> yb(field_bytes, 0);
  if (xlen > field_bytes || ylen > field_bytes) {
    BN_free(x); BN_free(y);
    EC_POINT_free(pub);
    EC_GROUP_free(group);
    BN_free(priv_bn);
    BN_CTX_free(ctx);
    throwRuntimeException(env, "coordinate size larger than field size");
    return nullptr;
  }
  // BN_bn2bin writes big-endian without leading zeros; place at right offset
  BN_bn2bin(x, xb.data() + (field_bytes - xlen));
  BN_bn2bin(y, yb.data() + (field_bytes - ylen));

  std::string Xb64 = base64UrlEncodeNoPad(xb.data(), (int)xb.size());
  std::string Yb64 = base64UrlEncodeNoPad(yb.data(), (int)yb.size());

  std::string out = Xb64 + "." + Yb64;

  BN_free(x); BN_free(y);
  EC_POINT_free(pub);
  EC_GROUP_free(group);
  BN_free(priv_bn);
  BN_CTX_free(ctx);

  return env->NewStringUTF(out.c_str());
}
