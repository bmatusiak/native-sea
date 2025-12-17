// native_seasign.cpp
// ECDSA sign/verify using OpenSSL EVP APIs (OpenSSL 3 compatible)

#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#define LOG_TAG "native_seasign"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static void throwRuntimeException(JNIEnv *env, const char *msg) {
  jclass exCls = env->FindClass("java/lang/RuntimeException");
  if (exCls) env->ThrowNew(exCls, msg);
}

static std::string toStdString(JNIEnv* env, jstring s) {
  if (s == nullptr) return std::string();
  const char* utf = env->GetStringUTFChars(s, nullptr);
  std::string out(utf);
  env->ReleaseStringUTFChars(s, utf);
  return out;
}

// URL-safe base64 decode (no padding)
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

static bool b64_decode(const char *in, std::vector<unsigned char> &out) {
  if (!in) return false;
  size_t len = strlen(in);
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bmem = BIO_new_mem_buf((void*)in, (int)len);
  if (!b64 || !bmem) {
    BIO_free_all(b64);
    BIO_free_all(bmem);
    return false;
  }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bmem);
  out.assign(len, 0);
  int decoded = BIO_read(b64, out.data(), (int)out.size());
  BIO_free_all(b64);
  if (decoded <= 0) return false;
  out.resize(decoded);
  return true;
}

static bool b64_encode(const unsigned char *data, int len, std::string &out) {
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bmem = BIO_new(BIO_s_mem());
  if (!b64 || !bmem) {
    BIO_free_all(b64);
    BIO_free_all(bmem);
    return false;
  }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bmem);
  BIO_write(b64, data, len);
  BIO_flush(b64);
  BUF_MEM *bptr = nullptr;
  BIO_get_mem_ptr(b64, &bptr);
  if (!bptr) {
    BIO_free_all(b64);
    return false;
  }
  out.assign(bptr->data, bptr->length);
  BIO_free_all(b64);
  return true;
}

extern "C" JNIEXPORT jstring JNICALL
Java_expo_modules_nativesea_SEASign_nativeSign(JNIEnv* env, jclass /*cls*/, jstring jprivB64, jbyteArray jdata) {
  std::string privB64 = toStdString(env, jprivB64);
  if (privB64.empty()) {
    throwRuntimeException(env, "nativeSign: priv empty");
    return nullptr;
  }
  auto privBytes = base64UrlDecode(privB64);
  if (privBytes.empty()) { throwRuntimeException(env, "nativeSign: failed to decode priv"); return nullptr; }

  jsize dataLen = env->GetArrayLength(jdata);
  std::vector<unsigned char> data((size_t)dataLen);
  env->GetByteArrayRegion(jdata, 0, dataLen, reinterpret_cast<jbyte*>(data.data()));

  // Create an EVP_PKEY from raw private key bytes using provider-based API (OpenSSL 3)
  EVP_PKEY *pkey = nullptr;
  LOGE("nativeSign: privBytes.size=%zu", privBytes.size());
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!pctx) { throwRuntimeException(env, "nativeSign: EVP_PKEY_CTX_new_from_name failed"); return nullptr; }
  if (EVP_PKEY_fromdata_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); throwRuntimeException(env, "nativeSign: EVP_PKEY_fromdata_init failed"); return nullptr; }
  // group name for prime256v1 / secp256r1
  OSSL_PARAM params[3];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"prime256v1", 0);
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void*)privBytes.data(), (size_t)privBytes.size());
  params[2] = OSSL_PARAM_construct_end();
  if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
    unsigned long e = ERR_get_error();
    char errbuf[256];
    ERR_error_string_n(e, errbuf, sizeof(errbuf));
    LOGE("EVP_PKEY_fromdata failed: %s", errbuf);
    EVP_PKEY_CTX_free(pctx);
    // Fail-fast: do not attempt legacy fallback here to avoid unsafe ownership/allocator issues.
    std::string emsg = std::string("nativeSign: EVP_PKEY_fromdata failed: ") + errbuf;
    EVP_PKEY_CTX_free(pctx);
    throwRuntimeException(env, emsg.c_str());
    return nullptr;
  }
  EVP_PKEY_CTX_free(pctx);

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) { EVP_PKEY_free(pkey); throwRuntimeException(env, "nativeSign: EVP_MD_CTX_new failed"); return nullptr; }
  if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
    EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throwRuntimeException(env, "nativeSign: DigestSignInit failed"); return nullptr; }
  if (EVP_DigestSignUpdate(mdctx, data.data(), (size_t)data.size()) != 1) {
    EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throwRuntimeException(env, "nativeSign: DigestSignUpdate failed"); return nullptr; }
  size_t derlen = 0;
  if (EVP_DigestSignFinal(mdctx, nullptr, &derlen) != 1) {
    EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throwRuntimeException(env, "nativeSign: DigestSignFinal(len) failed"); return nullptr; }
  std::vector<unsigned char> der(derlen);
  if (EVP_DigestSignFinal(mdctx, der.data(), &derlen) != 1) {
    EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throwRuntimeException(env, "nativeSign: DigestSignFinal failed"); return nullptr; }
  der.resize(derlen);
  EVP_MD_CTX_free(mdctx);

  const unsigned char *p = der.data();
  ECDSA_SIG* ecsig = d2i_ECDSA_SIG(nullptr, &p, (long)der.size());
  if (!ecsig) { EVP_PKEY_free(pkey); throwRuntimeException(env, "nativeSign: d2i_ECDSA_SIG failed"); return nullptr; }

  const BIGNUM *r, *s;
  ECDSA_SIG_get0(ecsig, &r, &s);

  // ensure fixed 32-byte output per component
  unsigned char outrs[64];
  memset(outrs, 0, sizeof(outrs));
  if (BN_bn2binpad(r, outrs, 32) < 0 || BN_bn2binpad(s, outrs + 32, 32) < 0) {
    ECDSA_SIG_free(ecsig); EVP_PKEY_free(pkey);
    throwRuntimeException(env, "nativeSign: BN_bn2binpad failed"); return nullptr;
  }

  std::string outB64;
  if (!b64_encode(outrs, 64, outB64)) {
    ECDSA_SIG_free(ecsig); EVP_PKEY_free(pkey);
    throwRuntimeException(env, "nativeSign: base64 encode failed"); return nullptr;
  }

  ECDSA_SIG_free(ecsig);
  EVP_PKEY_free(pkey);

  return env->NewStringUTF(outB64.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_expo_modules_nativesea_SEASign_nativeVerify(JNIEnv* env, jclass /*cls*/, jstring jpubXY, jbyteArray jdata, jstring jsigRSB64) {
  std::string pubXY = toStdString(env, jpubXY);
  std::string sigB64 = toStdString(env, jsigRSB64);
  if (pubXY.empty() || sigB64.empty()) { throwRuntimeException(env, "nativeVerify: inputs empty"); return JNI_FALSE; }

  size_t dot = pubXY.find('.');
  if (dot == std::string::npos) { throwRuntimeException(env, "nativeVerify: invalid pub format"); return JNI_FALSE; }
  std::string xb64 = pubXY.substr(0, dot);
  std::string yb64 = pubXY.substr(dot + 1);
  auto xbytes = base64UrlDecode(xb64);
  auto ybytes = base64UrlDecode(yb64);
  if (xbytes.empty() || ybytes.empty()) { throwRuntimeException(env, "nativeVerify: failed to decode pub coords"); return JNI_FALSE; }

  std::vector<unsigned char> sigrs;
  if (!b64_decode(sigB64.c_str(), sigrs)) { throwRuntimeException(env, "nativeVerify: failed to decode sig base64"); return JNI_FALSE; }
  if (sigrs.size() < 1) { throwRuntimeException(env, "nativeVerify: sig empty"); return JNI_FALSE; }

  // r||s raw expected; split in half
  size_t half = sigrs.size() / 2;
  if (half == 0) { throwRuntimeException(env, "nativeVerify: sig length invalid"); return JNI_FALSE; }

  BIGNUM* r = BN_bin2bn(sigrs.data(), (int)half, nullptr);
  BIGNUM* s = BN_bin2bn(sigrs.data() + half, (int)(sigrs.size() - half), nullptr);
  if (!r || !s) { if (r) BN_free(r); if (s) BN_free(s); throwRuntimeException(env, "nativeVerify: BN_bin2bn for sig failed"); return JNI_FALSE; }
  ECDSA_SIG* ecsig = ECDSA_SIG_new();
  if (!ecsig) { BN_free(r); BN_free(s); throwRuntimeException(env, "nativeVerify: ECDSA_SIG_new failed"); return JNI_FALSE; }
  if (ECDSA_SIG_set0(ecsig, r, s) != 1) { ECDSA_SIG_free(ecsig); BN_free(r); BN_free(s); throwRuntimeException(env, "nativeVerify: ECDSA_SIG_set0 failed"); return JNI_FALSE; }

  jsize dataLen = env->GetArrayLength(jdata);
  std::vector<unsigned char> data((size_t)dataLen);
  env->GetByteArrayRegion(jdata, 0, dataLen, reinterpret_cast<jbyte*>(data.data()));

  // Build public key octet string (uncompressed: 0x04 || X || Y)
  std::vector<unsigned char> pub_octet;
  pub_octet.reserve(1 + xbytes.size() + ybytes.size());
  pub_octet.push_back(0x04);
  pub_octet.insert(pub_octet.end(), xbytes.begin(), xbytes.end());
  pub_octet.insert(pub_octet.end(), ybytes.begin(), ybytes.end());

  // convert ECDSA_SIG to DER
  unsigned char *der = nullptr;
  int derlen = i2d_ECDSA_SIG(ecsig, &der);
  if (derlen <= 0 || !der) { ECDSA_SIG_free(ecsig); if(der) OPENSSL_free(der); throwRuntimeException(env, "nativeVerify: i2d_ECDSA_SIG failed"); return JNI_FALSE; }

  // Create EVP_PKEY from public octet using provider API (OpenSSL 3)
  EVP_PKEY *pkey = nullptr;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!pctx) { OPENSSL_free(der); ECDSA_SIG_free(ecsig); throwRuntimeException(env, "nativeVerify: EVP_PKEY_CTX_new_from_name failed"); return JNI_FALSE; }
  if (EVP_PKEY_fromdata_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); OPENSSL_free(der); ECDSA_SIG_free(ecsig); throwRuntimeException(env, "nativeVerify: EVP_PKEY_fromdata_init failed"); return JNI_FALSE; }
  OSSL_PARAM params[3];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"prime256v1", 0);
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pub_octet.data(), pub_octet.size());
  params[2] = OSSL_PARAM_construct_end();
  if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) { EVP_PKEY_CTX_free(pctx); OPENSSL_free(der); ECDSA_SIG_free(ecsig); throwRuntimeException(env, "nativeVerify: EVP_PKEY_fromdata failed"); return JNI_FALSE; }
  EVP_PKEY_CTX_free(pctx);

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) { EVP_PKEY_free(pkey); OPENSSL_free(der); ECDSA_SIG_free(ecsig); throwRuntimeException(env, "nativeVerify: EVP_MD_CTX_new failed"); return JNI_FALSE; }
  if (EVP_PKEY_fromdata_init(pctx) <= 0) { /* no-op here, handled earlier */ }
  if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
    EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); OPENSSL_free(der); ECDSA_SIG_free(ecsig); throwRuntimeException(env, "nativeVerify: DigestVerifyInit failed"); return JNI_FALSE; }
  if (EVP_DigestVerifyUpdate(mdctx, data.data(), (size_t)data.size()) != 1) {
    EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); OPENSSL_free(der); ECDSA_SIG_free(ecsig); throwRuntimeException(env, "nativeVerify: DigestVerifyUpdate failed"); return JNI_FALSE; }
  int rc = EVP_DigestVerifyFinal(mdctx, der, derlen);

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  OPENSSL_free(der);
  ECDSA_SIG_free(ecsig);

  if (rc == 1) return JNI_TRUE;
  return JNI_FALSE;
}
