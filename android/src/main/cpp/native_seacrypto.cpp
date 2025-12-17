// native_seacrypto.cpp
// AES-GCM encrypt/decrypt JNI implementations using OpenSSL EVP (non-deprecated APIs)

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

#define LOG_TAG "native_seacrypto"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// reuse url-safe base64 helpers compatible with other native code
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

extern "C" JNIEXPORT jstring JNICALL
Java_expo_modules_nativesea_SEACrypto_nativeEncryptAesGcm(JNIEnv *env, jclass /*cls*/, jstring jtextB64, jstring jkeyB64, jstring jivB64) {
  const char *textB64 = env->GetStringUTFChars(jtextB64, nullptr);
  const char *keyB64 = env->GetStringUTFChars(jkeyB64, nullptr);
  const char *ivB64 = env->GetStringUTFChars(jivB64, nullptr);
  std::string outB64;

  std::vector<unsigned char> text, key, iv;
  // AES inputs use standard base64 without URL-safe transformations
  bool ok = false;
  // decode text
  {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(textB64, (int)strlen(textB64));
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bmem);
    text.assign(strlen(textB64), 0);
    int decoded = BIO_read(b64, text.data(), (int)text.size());
    BIO_free_all(b64);
    if (decoded > 0) {
      text.resize(decoded);
      ok = true;
    }
  }
  if (ok) {
    auto decKey = base64UrlDecode(keyB64); // keys may be URL-safe or standard; try URL-safe first
    if (!decKey.empty()) { key = std::move(decKey); }
    else {
      BIO *b64 = BIO_new(BIO_f_base64());
      BIO *bmem = BIO_new_mem_buf(keyB64, (int)strlen(keyB64));
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
      BIO_push(b64, bmem);
      key.assign(strlen(keyB64), 0);
      int decoded = BIO_read(b64, key.data(), (int)key.size());
      BIO_free_all(b64);
      if (decoded > 0) key.resize(decoded); else ok = false;
    }
  }
  if (ok) {
    auto decIv = base64UrlDecode(ivB64);
    if (!decIv.empty()) { iv = std::move(decIv); }
    else {
      BIO *b64 = BIO_new(BIO_f_base64());
      BIO *bmem = BIO_new_mem_buf(ivB64, (int)strlen(ivB64));
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
      BIO_push(b64, bmem);
      iv.assign(strlen(ivB64), 0);
      int decoded = BIO_read(b64, iv.data(), (int)iv.size());
      BIO_free_all(b64);
      if (decoded > 0) iv.resize(decoded); else ok = false;
    }
  }
  env->ReleaseStringUTFChars(jtextB64, textB64);
  env->ReleaseStringUTFChars(jkeyB64, keyB64);
  env->ReleaseStringUTFChars(jivB64, ivB64);
  if (!ok) {
    throwRuntimeException(env, "Base64 decode failed in nativeEncryptAesGcm");
    return nullptr;
  }

  const EVP_CIPHER *cipher = nullptr;
  if (key.size() == 16) cipher = EVP_aes_128_gcm();
  else if (key.size() == 24) cipher = EVP_aes_192_gcm();
  else if (key.size() == 32) cipher = EVP_aes_256_gcm();
  else {
    throwRuntimeException(env, "Unsupported AES key length in nativeEncryptAesGcm");
    return nullptr;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throwRuntimeException(env, "EVP_CIPHER_CTX_new failed");
    return nullptr;
  }

  int rc = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
  if (rc != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throwRuntimeException(env, "EVP_EncryptInit_ex failed");
    return nullptr;
  }
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr)) {
    EVP_CIPHER_CTX_free(ctx);
    throwRuntimeException(env, "EVP_CTRL_GCM_SET_IVLEN failed");
    return nullptr;
  }
  rc = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
  if (rc != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throwRuntimeException(env, "EVP_EncryptInit_ex set key/iv failed");
    return nullptr;
  }

  std::vector<unsigned char> outbuf(text.size() + EVP_CIPHER_block_size(cipher));
  int outlen = 0;
  rc = EVP_EncryptUpdate(ctx, outbuf.data(), &outlen, text.data(), (int)text.size());
  if (rc != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throwRuntimeException(env, "EVP_EncryptUpdate failed");
    return nullptr;
  }
  int tmplen = 0;
  rc = EVP_EncryptFinal_ex(ctx, outbuf.data() + outlen, &tmplen);
  if (rc != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throwRuntimeException(env, "EVP_EncryptFinal_ex failed");
    return nullptr;
  }
  outlen += tmplen;

  unsigned char tag[16];
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
    EVP_CIPHER_CTX_free(ctx);
    throwRuntimeException(env, "EVP_CTRL_GCM_GET_TAG failed");
    return nullptr;
  }
  EVP_CIPHER_CTX_free(ctx);

  // Combined ciphertext||tag
  std::vector<unsigned char> combined;
  combined.reserve(outlen + 16);
  combined.insert(combined.end(), outbuf.begin(), outbuf.begin() + outlen);
  combined.insert(combined.end(), tag, tag + 16);

  if (!b64_encode(combined.data(), (int)combined.size(), outB64)) {
    throwRuntimeException(env, "Base64 encode failed in nativeEncryptAesGcm");
    return nullptr;
  }

  return env->NewStringUTF(outB64.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_expo_modules_nativesea_SEACrypto_nativeDecryptAesGcm(JNIEnv *env, jclass /*cls*/, jstring jciphertextB64, jstring jkeyB64, jstring jivB64, jstring jtagB64) {
  const char *ciphertextB64 = env->GetStringUTFChars(jciphertextB64, nullptr);
  const char *keyB64 = env->GetStringUTFChars(jkeyB64, nullptr);
  const char *ivB64 = env->GetStringUTFChars(jivB64, nullptr);
  const char *tagB64 = env->GetStringUTFChars(jtagB64, nullptr);

  std::vector<unsigned char> ciphertext, key, iv, tag;
  bool ok = b64_decode(ciphertextB64, ciphertext) && b64_decode(keyB64, key) && b64_decode(ivB64, iv) && b64_decode(tagB64, tag);
  env->ReleaseStringUTFChars(jciphertextB64, ciphertextB64);
  env->ReleaseStringUTFChars(jkeyB64, keyB64);
  env->ReleaseStringUTFChars(jivB64, ivB64);
  env->ReleaseStringUTFChars(jtagB64, tagB64);
  if (!ok) {
    throwRuntimeException(env, "Base64 decode failed in nativeDecryptAesGcm");
    return nullptr;
  }

  const EVP_CIPHER *cipher = nullptr;
  if (key.size() == 16) cipher = EVP_aes_128_gcm();
  else if (key.size() == 24) cipher = EVP_aes_192_gcm();
  else if (key.size() == 32) cipher = EVP_aes_256_gcm();
  else {
    throwRuntimeException(env, "Unsupported AES key length in nativeDecryptAesGcm");
    return nullptr;
  }

  auto try_decrypt = [&](const unsigned char *ct, int ct_len, const unsigned char *tg, int tg_len, std::string &outStr) -> bool {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
      EVP_CIPHER_CTX_free(ctx); return false;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr)) {
      EVP_CIPHER_CTX_free(ctx); return false;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx); return false;
    }
    std::vector<unsigned char> outbuf(ct_len + EVP_CIPHER_block_size(cipher));
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, outbuf.data(), &outlen, ct, ct_len) != 1) {
      EVP_CIPHER_CTX_free(ctx); return false;
    }
    // set expected tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tg_len, (void *)tg)) {
      EVP_CIPHER_CTX_free(ctx); return false;
    }
    int tmplen = 0;
    int rc = EVP_DecryptFinal_ex(ctx, outbuf.data() + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1) return false; // tag verification failed
    outlen += tmplen;
    outStr.assign(reinterpret_cast<char *>(outbuf.data()), outlen);
    return true;
  };

  std::string result;
  // try ciphertext||tag order
  if (try_decrypt(ciphertext.data(), (int)ciphertext.size(), tag.data(), (int)tag.size(), result)) {
    return env->NewStringUTF(result.c_str());
  }

  throwRuntimeException(env, "nativeDecryptAesGcm: decryption failed (tag mismatch or invalid data)");
  return nullptr;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_expo_modules_nativesea_SEASecret_nativeDerive(JNIEnv* env, jclass /*cls*/, jstring jprivB64, jstring jpubXY) {
  std::string privB64 = toStdString(env, jprivB64);
  std::string pubXY = toStdString(env, jpubXY);
  if (privB64.empty() || pubXY.empty()) {
    throwRuntimeException(env, "nativeDerive: inputs empty");
    return nullptr;
  }

  auto privBytes = base64UrlDecode(privB64);
  if (privBytes.empty()) {
    throwRuntimeException(env, "nativeDerive: failed to decode priv base64");
    return nullptr;
  }

  size_t dot = pubXY.find('.');
  if (dot == std::string::npos) {
    throwRuntimeException(env, "nativeDerive: invalid pub format");
    return nullptr;
  }
  std::string xb64 = pubXY.substr(0, dot);
  std::string yb64 = pubXY.substr(dot + 1);
  auto xbytes = base64UrlDecode(xb64);
  auto ybytes = base64UrlDecode(yb64);
  if (xbytes.empty() || ybytes.empty()) {
    throwRuntimeException(env, "nativeDerive: failed to decode pub coords");
    return nullptr;
  }

  int nid = NID_X9_62_prime256v1;
  EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
  if (!group) { throwRuntimeException(env, "nativeDerive: EC_GROUP_new_by_curve_name failed"); return nullptr; }
  BN_CTX* ctx = BN_CTX_new();
  if (!ctx) { EC_GROUP_free(group); throwRuntimeException(env, "nativeDerive: BN_CTX_new failed"); return nullptr; }

  BIGNUM* priv_bn = BN_bin2bn(privBytes.data(), (int)privBytes.size(), nullptr);
  if (!priv_bn) { BN_CTX_free(ctx); EC_GROUP_free(group); throwRuntimeException(env, "nativeDerive: BN_bin2bn failed"); return nullptr; }

  EC_POINT* pub = EC_POINT_new(group);
  if (!pub) { BN_free(priv_bn); BN_CTX_free(ctx); EC_GROUP_free(group); throwRuntimeException(env, "nativeDerive: EC_POINT_new failed"); return nullptr; }

  BIGNUM* x_bn = BN_bin2bn(xbytes.data(), (int)xbytes.size(), nullptr);
  BIGNUM* y_bn = BN_bin2bn(ybytes.data(), (int)ybytes.size(), nullptr);
  if (!x_bn || !y_bn) {
    if (x_bn) BN_free(x_bn); if (y_bn) BN_free(y_bn);
    EC_POINT_free(pub); BN_free(priv_bn); BN_CTX_free(ctx); EC_GROUP_free(group);
    throwRuntimeException(env, "nativeDerive: BN_bin2bn for coords failed");
    return nullptr;
  }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (1 != EC_POINT_set_affine_coordinates(group, pub, x_bn, y_bn, ctx)) {
#else
  if (1 != EC_POINT_set_affine_coordinates_GFp(group, pub, x_bn, y_bn, ctx)) {
#endif
    BN_free(x_bn); BN_free(y_bn); EC_POINT_free(pub); BN_free(priv_bn); BN_CTX_free(ctx); EC_GROUP_free(group);
    throwRuntimeException(env, "nativeDerive: EC_POINT_set_affine_coordinates failed");
    return nullptr;
  }

  EC_POINT* shared = EC_POINT_new(group);
  if (!shared) {
    BN_free(x_bn); BN_free(y_bn); EC_POINT_free(pub); BN_free(priv_bn); BN_CTX_free(ctx); EC_GROUP_free(group);
    throwRuntimeException(env, "nativeDerive: EC_POINT_new(shared) failed");
    return nullptr;
  }

  if (1 != EC_POINT_mul(group, shared, nullptr, pub, priv_bn, ctx)) {
    EC_POINT_free(shared); BN_free(x_bn); BN_free(y_bn); EC_POINT_free(pub); BN_free(priv_bn); BN_CTX_free(ctx); EC_GROUP_free(group);
    throwRuntimeException(env, "nativeDerive: EC_POINT_mul failed");
    return nullptr;
  }

  BIGNUM* sx = BN_new();
  BIGNUM* sy = BN_new();
  if (!sx || !sy) {
    if (sx) BN_free(sx); if (sy) BN_free(sy);
    EC_POINT_free(shared); BN_free(x_bn); BN_free(y_bn); EC_POINT_free(pub); BN_free(priv_bn); BN_CTX_free(ctx); EC_GROUP_free(group);
    throwRuntimeException(env, "nativeDerive: BN_new failed");
    return nullptr;
  }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (1 != EC_POINT_get_affine_coordinates(group, shared, sx, sy, ctx)) {
#else
  if (1 != EC_POINT_get_affine_coordinates_GFp(group, shared, sx, sy, ctx)) {
#endif
    BN_free(sx); BN_free(sy); EC_POINT_free(shared); BN_free(x_bn); BN_free(y_bn); EC_POINT_free(pub); BN_free(priv_bn); BN_CTX_free(ctx); EC_GROUP_free(group);
    throwRuntimeException(env, "nativeDerive: EC_POINT_get_affine_coordinates failed");
    return nullptr;
  }

  int s_len = BN_num_bytes(sx);
  std::vector<unsigned char> s_bytes(s_len);
  BN_bn2bin(sx, s_bytes.data());

  BN_free(sx); BN_free(sy); EC_POINT_free(shared); BN_free(x_bn); BN_free(y_bn); EC_POINT_free(pub); BN_free(priv_bn); BN_CTX_free(ctx); EC_GROUP_free(group);

  jbyteArray out = env->NewByteArray((jsize)s_bytes.size());
  if (!out) {
    throwRuntimeException(env, "nativeDerive: NewByteArray failed");
    return nullptr;
  }
  env->SetByteArrayRegion(out, 0, (jsize)s_bytes.size(), reinterpret_cast<const jbyte*>(s_bytes.data()));
  return out;
}
