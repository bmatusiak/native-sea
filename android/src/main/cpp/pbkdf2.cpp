#include <jni.h>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>

extern "C" JNIEXPORT jbyteArray JNICALL
Java_expo_modules_nativesea_SEAWork_nativePbkdf2(JNIEnv* env, jclass /*cls*/, jstring jpwd, jbyteArray jsalt, jint jiter, jint jkeyLenBits) {
    if (jpwd == nullptr) return nullptr;

    const char* pwdChars = env->GetStringUTFChars(jpwd, nullptr);
    if (!pwdChars) return nullptr;
    const std::string pwd(pwdChars);
    env->ReleaseStringUTFChars(jpwd, pwdChars);

    jsize saltLen = 0;
    jbyte* saltBuf = nullptr;
    if (jsalt != nullptr) {
        saltLen = env->GetArrayLength(jsalt);
        saltBuf = env->GetByteArrayElements(jsalt, nullptr);
    }

    int iter = (int) jiter;
    int keyLenBytes = (int) jkeyLenBits / 8;
    if (keyLenBytes <= 0) {
        if (saltBuf) env->ReleaseByteArrayElements(jsalt, saltBuf, JNI_ABORT);
        return nullptr;
    }

    std::vector<unsigned char> out(keyLenBytes);

    const EVP_MD* md = EVP_sha256();
    if (!md) {
        if (saltBuf) env->ReleaseByteArrayElements(jsalt, saltBuf, JNI_ABORT);
        return nullptr;
    }

    int ok = PKCS5_PBKDF2_HMAC(pwd.c_str(), (int)pwd.size(), (unsigned char*)saltBuf, (int)saltLen, iter, md, keyLenBytes, out.data());

    if (saltBuf) env->ReleaseByteArrayElements(jsalt, saltBuf, JNI_ABORT);

    if (ok != 1) return nullptr;

    jbyteArray result = env->NewByteArray(keyLenBytes);
    if (!result) return nullptr;
    env->SetByteArrayRegion(result, 0, keyLenBytes, (jbyte*)out.data());
    return result;
}
