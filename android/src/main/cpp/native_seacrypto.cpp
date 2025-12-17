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

#define LOG_TAG "native_seacrypto"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static bool b64_decode(const std::string &in, std::vector<unsigned char> &out) {
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bmem = BIO_new_mem_buf(in.data(), (int)in.size());
  if (!b64 || !bmem) {
    BIO_free_all(b64);
    BIO_free_all(bmem);
    return false;
  }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bmem);
  out.assign(in.size(), 0);
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

static void throwRuntimeException(JNIEnv *env, const char *msg) {
  jclass exCls = env->FindClass("java/lang/RuntimeException");
  if (exCls) env->ThrowNew(exCls, msg);
}

extern "C" JNIEXPORT jstring JNICALL
Java_expo_modules_nativesea_SEACrypto_nativeEncryptAesGcm(JNIEnv *env, jclass /*cls*/, jstring jtextB64, jstring jkeyB64, jstring jivB64) {
  const char *textB64 = env->GetStringUTFChars(jtextB64, nullptr);
  const char *keyB64 = env->GetStringUTFChars(jkeyB64, nullptr);
  const char *ivB64 = env->GetStringUTFChars(jivB64, nullptr);
  std::string outB64;

  std::vector<unsigned char> text, key, iv;
  bool ok = b64_decode(textB64, text) && b64_decode(keyB64, key) && b64_decode(ivB64, iv);
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
