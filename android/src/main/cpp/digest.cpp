#include <jni.h>
#include <string>
#include <vector>
#include <openssl/evp.h>

extern "C" JNIEXPORT jbyteArray JNICALL
Java_expo_modules_nativesea_SEAWork_nativeDigest(JNIEnv* env, jclass /*cls*/, jstring algo, jbyteArray data) {
    if (algo == nullptr) return nullptr;

    const char* algChars = env->GetStringUTFChars(algo, nullptr);
    if (!algChars) return nullptr;
    const std::string algName(algChars);
    env->ReleaseStringUTFChars(algo, algChars);

    const EVP_MD* md = EVP_get_digestbyname(algName.c_str());
    if (!md) {
        return nullptr;
    }

    jbyte* bytes = nullptr;
    jsize len = 0;
    if (data != nullptr) {
        len = env->GetArrayLength(data);
        bytes = env->GetByteArrayElements(data, nullptr);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        if (bytes) env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
        return nullptr;
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        if (bytes) env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
        return nullptr;
    }

    if (len > 0 && bytes) {
        EVP_DigestUpdate(ctx, (unsigned char*)bytes, (size_t)len);
    }

    unsigned int outlen = EVP_MD_size(md);
    std::vector<unsigned char> out(outlen);
    if (EVP_DigestFinal_ex(ctx, out.data(), &outlen) != 1) {
        EVP_MD_CTX_free(ctx);
        if (bytes) env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
        return nullptr;
    }

    EVP_MD_CTX_free(ctx);
    if (bytes) env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);

    jbyteArray result = env->NewByteArray(outlen);
    if (!result) return nullptr;
    env->SetByteArrayRegion(result, 0, outlen, (jbyte*)out.data());
    return result;
}
