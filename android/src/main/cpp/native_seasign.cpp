// native_seasign.cpp
// ECDSA P-256 SHA-256 sign/verify using OpenSSL 3.x EVP APIs.
// Produces/consumes "raw" 64-byte signatures (r||s, 32 bytes each).

#include <jni.h>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static void throwRuntimeException(JNIEnv* env, const char* msg) {
  jclass ex = env->FindClass("java/lang/RuntimeException");
  if (ex) env->ThrowNew(ex, msg);
}

// Gun SEA uses WebCrypto ECDSA with { hash: 'SHA-256' } over an input that is
// already sha256(message). WebCrypto hashes the provided data again internally.
// To interop, native code must compute SHA-256(data) and then ECDSA-sign/verify
// that digest.
static bool sha256_bytes(const unsigned char* data, size_t len, unsigned char out[32]) {
  if (!data && len != 0) return false;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return false;
  bool ok = (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1);
  if (ok && len > 0) ok = (EVP_DigestUpdate(ctx, data, len) == 1);
  unsigned int outLen = 0;
  if (ok) ok = (EVP_DigestFinal_ex(ctx, out, &outLen) == 1);
  EVP_MD_CTX_free(ctx);
  return ok && outLen == 32;
}

// Some SEA / elliptic.js verification paths expect canonical ("low-S") ECDSA
// signatures. Normalize `s` to be <= n/2 for P-256 where n is the curve order.
static bool p256_normalize_low_s(const BIGNUM* sIn, BIGNUM** sOut) {
  if (!sIn || !sOut) return false;
  *sOut = nullptr;

  // P-256 / secp256r1 curve order (n)
  // n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  BIGNUM* n = nullptr;
  if (BN_hex2bn(&n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551") == 0 || !n) {
    if (n) BN_free(n);
    return false;
  }

  BIGNUM* half = BN_dup(n);
  if (!half) {
    BN_free(n);
    return false;
  }
  BN_rshift1(half, half);

  BIGNUM* s = BN_dup(sIn);
  if (!s) {
    BN_free(half);
    BN_free(n);
    return false;
  }

  if (BN_cmp(s, half) > 0) {
    // s = n - s
    if (BN_sub(s, n, s) != 1) {
      BN_free(s);
      BN_free(half);
      BN_free(n);
      return false;
    }
  }

  BN_free(half);
  BN_free(n);
  *sOut = s;
  return true;
}

static std::string toStdString(JNIEnv* env, jstring s) {
  if (s == nullptr) return std::string();
  const char* utf = env->GetStringUTFChars(s, nullptr);
  std::string out(utf ? utf : "");
  if (utf) env->ReleaseStringUTFChars(s, utf);
  return out;
}

static std::vector<unsigned char> base64UrlDecode(const std::string& in) {
  std::string s = in;
  for (char& c : s) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  size_t mod = s.size() % 4;
  if (mod) s.append(4 - mod, '=');

  BIO* b64 = BIO_new(BIO_f_base64());
  if (!b64) return {};
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO* bmem = BIO_new_mem_buf(s.data(), (int)s.size());
  if (!bmem) {
    BIO_free_all(b64);
    return {};
  }
  bmem = BIO_push(b64, bmem);

  std::vector<unsigned char> out(s.size());
  int decoded = BIO_read(bmem, out.data(), (int)out.size());
  BIO_free_all(bmem);
  if (decoded <= 0) return {};
  out.resize(decoded);
  return out;
}

static bool leftPadTo(std::vector<unsigned char>& bytes, size_t size) {
  if (bytes.size() == size) return true;
  if (bytes.size() > size) return false;
  std::vector<unsigned char> out(size, 0);
  // copy to the right (big-endian padding)
  memcpy(out.data() + (size - bytes.size()), bytes.data(), bytes.size());
  bytes.swap(out);
  return true;
}

static bool bigEndianBytesToNativeBnBytes(const std::vector<unsigned char>& be, std::vector<unsigned char>* nativeOut) {
  if (!nativeOut) return false;
  nativeOut->clear();

  // Convert to a BIGNUM assuming big-endian unsigned bytes (same as BN_bin2bn usage
  // elsewhere in this repo), then export to OpenSSL's "native" bignum byte encoding
  // expected by OSSL_PARAM BIGNUM helpers.
  BIGNUM* bn = BN_bin2bn(be.data(), static_cast<int>(be.size()), nullptr);
  if (!bn) return false;

  // Keep the fixed-width representation for P-256 private scalars.
  nativeOut->assign(32, 0);
  if (BN_bn2nativepad(bn, nativeOut->data(), nativeOut->size()) != static_cast<int>(nativeOut->size())) {
    BN_free(bn);
    nativeOut->clear();
    return false;
  }

  BN_free(bn);
  return true;
}

static EVP_PKEY* makeEcPrivateKeyP256(const std::vector<unsigned char>& priv32) {
  if (priv32.size() != 32) return nullptr;

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!ctx) return nullptr;
  if (EVP_PKEY_fromdata_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return nullptr;
  }

  static char groupName[] = "prime256v1";

  std::vector<unsigned char> privBnNative;
  if (!bigEndianBytesToNativeBnBytes(priv32, &privBnNative)) {
    EVP_PKEY_CTX_free(ctx);
    return nullptr;
  }

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, groupName, 0),
      // Private scalar as native-encoded BN bytes (OSSL_PARAM BIGNUM encoding).
      OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, privBnNative.data(), privBnNative.size()),
      OSSL_PARAM_construct_end(),
  };

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return nullptr;
  }

  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

static EVP_PKEY* makeEcPublicKeyP256FromXY(const std::vector<unsigned char>& x32, const std::vector<unsigned char>& y32) {
  if (x32.size() != 32 || y32.size() != 32) return nullptr;

  unsigned char point[65];
  point[0] = 0x04; // uncompressed
  memcpy(point + 1, x32.data(), 32);
  memcpy(point + 33, y32.data(), 32);

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!ctx) return nullptr;
  if (EVP_PKEY_fromdata_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return nullptr;
  }

  static char groupName[] = "prime256v1";
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, groupName, 0),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point)),
      OSSL_PARAM_construct_end(),
  };

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return nullptr;
  }

  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_expo_modules_nativesea_SEASign_nativeSign(JNIEnv* env, jclass /*cls*/, jstring jprivKeyB64Url, jbyteArray jdata) {
  std::string privB64 = toStdString(env, jprivKeyB64Url);
  if (privB64.empty()) {
    throwRuntimeException(env, "nativeSign: privKey empty");
    return nullptr;
  }

  std::vector<unsigned char> privBytes = base64UrlDecode(privB64);
  if (privBytes.empty()) {
    throwRuntimeException(env, "nativeSign: failed to decode privKey base64url");
    return nullptr;
  }
  if (!leftPadTo(privBytes, 32)) {
    throwRuntimeException(env, "nativeSign: privKey wrong length");
    return nullptr;
  }

  jsize dataLen = 0;
  jbyte* dataBuf = nullptr;
  if (jdata != nullptr) {
    dataLen = env->GetArrayLength(jdata);
    dataBuf = env->GetByteArrayElements(jdata, nullptr);
  }

  EVP_PKEY* pkey = makeEcPrivateKeyP256(privBytes);
  if (!pkey) {
    if (dataBuf) env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeSign: failed to build EC private key");
    return nullptr;
  }

  if (dataLen <= 0 || !dataBuf) {
    EVP_PKEY_free(pkey);
    if (dataBuf) env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeSign: data is empty");
    return nullptr;
  }

  // WebCrypto ECDSA hashes the provided data; Gun SEA passes sha256(message)
  // into ECDSA-with-SHA256, effectively signing sha256(sha256(message)).
  unsigned char digest[32];
  if (!sha256_bytes(reinterpret_cast<unsigned char*>(dataBuf), static_cast<size_t>(dataLen), digest)) {
    EVP_PKEY_free(pkey);
    env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeSign: sha256(data) failed");
    return nullptr;
  }

  EVP_PKEY_CTX* signCtx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!signCtx) {
    EVP_PKEY_free(pkey);
    env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeSign: EVP_PKEY_CTX_new failed");
    return nullptr;
  }
  if (EVP_PKEY_sign_init(signCtx) <= 0) {
    EVP_PKEY_CTX_free(signCtx);
    EVP_PKEY_free(pkey);
    env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeSign: EVP_PKEY_sign_init failed");
    return nullptr;
  }
  // Indicate the digest algorithm that produced the input.
  if (EVP_PKEY_CTX_set_signature_md(signCtx, EVP_sha256()) <= 0) {
    EVP_PKEY_CTX_free(signCtx);
    EVP_PKEY_free(pkey);
    env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeSign: EVP_PKEY_CTX_set_signature_md failed");
    return nullptr;
  }

  size_t derLen = 0;
  if (EVP_PKEY_sign(signCtx, nullptr, &derLen, digest, sizeof(digest)) <= 0 || derLen == 0) {
    EVP_PKEY_CTX_free(signCtx);
    EVP_PKEY_free(pkey);
    env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeSign: EVP_PKEY_sign size query failed");
    return nullptr;
  }

  std::vector<unsigned char> der(derLen);
  if (EVP_PKEY_sign(signCtx, der.data(), &derLen, digest, sizeof(digest)) <= 0) {
    EVP_PKEY_CTX_free(signCtx);
    EVP_PKEY_free(pkey);
    env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeSign: EVP_PKEY_sign failed");
    return nullptr;
  }
  der.resize(derLen);

  EVP_PKEY_CTX_free(signCtx);
  EVP_PKEY_free(pkey);
  env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);

  const unsigned char* p = der.data();
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, (long)der.size());
  if (!sig) {
    throwRuntimeException(env, "nativeSign: failed to parse DER signature");
    return nullptr;
  }

  const BIGNUM* r = nullptr;
  const BIGNUM* s = nullptr;
  ECDSA_SIG_get0(sig, &r, &s);
  if (!r || !s) {
    ECDSA_SIG_free(sig);
    throwRuntimeException(env, "nativeSign: ECDSA_SIG_get0 failed");
    return nullptr;
  }

  BIGNUM* sLow = nullptr;
  if (!p256_normalize_low_s(s, &sLow) || !sLow) {
    ECDSA_SIG_free(sig);
    throwRuntimeException(env, "nativeSign: failed to normalize signature (low-S)");
    return nullptr;
  }

  unsigned char out64[64];
  if (BN_bn2binpad(r, out64, 32) != 32 || BN_bn2binpad(sLow, out64 + 32, 32) != 32) {
    BN_free(sLow);
    ECDSA_SIG_free(sig);
    throwRuntimeException(env, "nativeSign: failed to serialize r/s");
    return nullptr;
  }
  BN_free(sLow);
  ECDSA_SIG_free(sig);

  jbyteArray result = env->NewByteArray(64);
  if (!result) {
    throwRuntimeException(env, "nativeSign: NewByteArray failed");
    return nullptr;
  }
  env->SetByteArrayRegion(result, 0, 64, reinterpret_cast<const jbyte*>(out64));
  return result;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_expo_modules_nativesea_SEASign_nativeVerify(JNIEnv* env, jclass /*cls*/, jstring jpubXY, jbyteArray jdata, jbyteArray jsigRS) {
  std::string pubXY = toStdString(env, jpubXY);
  if (pubXY.empty()) {
    throwRuntimeException(env, "nativeVerify: pubKey empty");
    return JNI_FALSE;
  }

  // Allow escaped dots coming from some JS serializations.
  // (Kotlin side also normalizes, but keep this robust.)
  for (size_t pos = 0; (pos = pubXY.find("\\." , pos)) != std::string::npos; ) {
    pubXY.replace(pos, 2, ".");
    pos += 1;
  }

  size_t dot = pubXY.find('.');
  if (dot == std::string::npos) {
    throwRuntimeException(env, "nativeVerify: invalid pubKey format (expected X.Y)");
    return JNI_FALSE;
  }

  std::vector<unsigned char> xBytes = base64UrlDecode(pubXY.substr(0, dot));
  std::vector<unsigned char> yBytes = base64UrlDecode(pubXY.substr(dot + 1));
  if (xBytes.empty() || yBytes.empty()) {
    throwRuntimeException(env, "nativeVerify: failed to decode pubKey base64url");
    return JNI_FALSE;
  }
  if (!leftPadTo(xBytes, 32) || !leftPadTo(yBytes, 32)) {
    throwRuntimeException(env, "nativeVerify: pubKey coordinate wrong length");
    return JNI_FALSE;
  }

  jsize sigLen = (jsigRS != nullptr) ? env->GetArrayLength(jsigRS) : 0;
  if (sigLen != 64) {
    throwRuntimeException(env, "nativeVerify: signature must be 64 bytes (r||s)");
    return JNI_FALSE;
  }

  jbyte* sigBuf = env->GetByteArrayElements(jsigRS, nullptr);
  if (!sigBuf) {
    throwRuntimeException(env, "nativeVerify: GetByteArrayElements(sig) failed");
    return JNI_FALSE;
  }

  BIGNUM* r = BN_bin2bn(reinterpret_cast<unsigned char*>(sigBuf), 32, nullptr);
  BIGNUM* s = BN_bin2bn(reinterpret_cast<unsigned char*>(sigBuf + 32), 32, nullptr);
  env->ReleaseByteArrayElements(jsigRS, sigBuf, JNI_ABORT);
  if (!r || !s) {
    if (r) BN_free(r);
    if (s) BN_free(s);
    throwRuntimeException(env, "nativeVerify: BN_bin2bn failed");
    return JNI_FALSE;
  }

  ECDSA_SIG* ecsig = ECDSA_SIG_new();
  if (!ecsig) {
    BN_free(r); BN_free(s);
    throwRuntimeException(env, "nativeVerify: ECDSA_SIG_new failed");
    return JNI_FALSE;
  }
  if (ECDSA_SIG_set0(ecsig, r, s) != 1) {
    ECDSA_SIG_free(ecsig);
    BN_free(r); BN_free(s);
    throwRuntimeException(env, "nativeVerify: ECDSA_SIG_set0 failed");
    return JNI_FALSE;
  }

  int derLen = i2d_ECDSA_SIG(ecsig, nullptr);
  if (derLen <= 0) {
    ECDSA_SIG_free(ecsig);
    throwRuntimeException(env, "nativeVerify: i2d_ECDSA_SIG size failed");
    return JNI_FALSE;
  }
  std::vector<unsigned char> der((size_t)derLen);
  unsigned char* derPtr = der.data();
  if (i2d_ECDSA_SIG(ecsig, &derPtr) != derLen) {
    ECDSA_SIG_free(ecsig);
    throwRuntimeException(env, "nativeVerify: i2d_ECDSA_SIG encode failed");
    return JNI_FALSE;
  }
  ECDSA_SIG_free(ecsig);

  EVP_PKEY* pkey = makeEcPublicKeyP256FromXY(xBytes, yBytes);
  if (!pkey) {
    throwRuntimeException(env, "nativeVerify: failed to build EC public key");
    return JNI_FALSE;
  }

  jsize dataLen = 0;
  jbyte* dataBuf = nullptr;
  if (jdata != nullptr) {
    dataLen = env->GetArrayLength(jdata);
    dataBuf = env->GetByteArrayElements(jdata, nullptr);
  }

  if (dataLen <= 0 || !dataBuf) {
    EVP_PKEY_free(pkey);
    if (dataBuf) env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeVerify: data is empty");
    return JNI_FALSE;
  }

  unsigned char digest[32];
  if (!sha256_bytes(reinterpret_cast<unsigned char*>(dataBuf), static_cast<size_t>(dataLen), digest)) {
    EVP_PKEY_free(pkey);
    env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeVerify: sha256(data) failed");
    return JNI_FALSE;
  }

  // Verify the digest directly (no extra hashing).
  EVP_PKEY_CTX* verifyCtx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!verifyCtx) {
    EVP_PKEY_free(pkey);
    env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeVerify: EVP_PKEY_CTX_new failed");
    return JNI_FALSE;
  }
  if (EVP_PKEY_verify_init(verifyCtx) <= 0) {
    EVP_PKEY_CTX_free(verifyCtx);
    EVP_PKEY_free(pkey);
    env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeVerify: EVP_PKEY_verify_init failed");
    return JNI_FALSE;
  }
  if (EVP_PKEY_CTX_set_signature_md(verifyCtx, EVP_sha256()) <= 0) {
    EVP_PKEY_CTX_free(verifyCtx);
    EVP_PKEY_free(pkey);
    env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);
    throwRuntimeException(env, "nativeVerify: EVP_PKEY_CTX_set_signature_md failed");
    return JNI_FALSE;
  }

  int ok = EVP_PKEY_verify(verifyCtx, der.data(), der.size(), digest, sizeof(digest));

  EVP_PKEY_CTX_free(verifyCtx);
  EVP_PKEY_free(pkey);
  env->ReleaseByteArrayElements(jdata, dataBuf, JNI_ABORT);

  if (ok == 1) return JNI_TRUE;
  if (ok == 0) return JNI_FALSE; // signature mismatch

  throwRuntimeException(env, "nativeVerify: EVP_PKEY_verify error");
  return JNI_FALSE;
}
