package expo.modules.nativesea

import android.util.Base64
import org.spongycastle.crypto.Digest
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.spongycastle.crypto.params.KeyParameter
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

object SEAWork {
  init {
    try {
      System.loadLibrary("native_sea")
    } catch (e: UnsatisfiedLinkError) {
      // library may not be available during some IDE tasks - fall back to Java
    }
  }

  @JvmStatic
  private external fun nativeDigest(algo: String, data: ByteArray?): ByteArray?

  @JvmStatic
  private external fun nativePbkdf2(pwd: String, salt: ByteArray?, iter: Int, keyLenBits: Int): ByteArray?

  @JvmStatic
  fun pbkdf2(pwd: String, salt: String, iter: Int?, bitSize: Int?): String {
    val iters = iter ?: 1000
    val bits = bitSize ?: 256

    // Convert salt (supports comma-separated numeric or UTF-8 string)
    val saltBytes: ByteArray = if (salt.contains(",")) {
      val parts = salt.split(",").map { it.trim() }
      val bytes = ByteArray(parts.size)
      for (i in parts.indices) {
        val v = parts[i]
        if (v.isEmpty()) continue
        bytes[i] = v.toInt().toByte()
      }
      bytes
    } else {
      salt.toByteArray(StandardCharsets.UTF_8)
    }

    if (NativeSeaModule.useNativeCrypto) {
      try {
        val out = nativePbkdf2(pwd, saltBytes, iters, bits)
        if (out != null) return Base64.encodeToString(out, Base64.NO_WRAP)
        throw IllegalStateException("nativePbkdf2 returned null")
      } catch (e: Throwable) {
        throw RuntimeException("nativePbkdf2 failed", e)
      }
    }else{
      val algorithmDigest: Digest = SHA256Digest()
      val gen = PKCS5S2ParametersGenerator(algorithmDigest)
      gen.init(pwd.toByteArray(StandardCharsets.UTF_8), saltBytes, iters)
      val key = (gen.generateDerivedParameters(bits)) as KeyParameter
      return Base64.encodeToString(key.key, Base64.NO_WRAP)
    }
  }

  @JvmStatic
  fun pbkdf2(pwd: String, saltList: List<Int>, iter: Int?, bitSize: Int?): String {
    val iters = iter ?: 1000
    val bits = bitSize ?: 256
    val saltBytes = SEAUtil.readableListToByteArray(saltList)

    if (NativeSeaModule.useNativeCrypto) {
      try {
        val out = nativePbkdf2(pwd, saltBytes, iters, bits)
        if (out != null) return Base64.encodeToString(out, Base64.NO_WRAP)
        throw IllegalStateException("nativePbkdf2 returned null")
      } catch (e: Throwable) {
        throw RuntimeException("nativePbkdf2 failed", e)
      }
    } else {
      val algorithmDigest: Digest = SHA256Digest()
      val gen = PKCS5S2ParametersGenerator(algorithmDigest)
      gen.init(pwd.toByteArray(StandardCharsets.UTF_8), saltBytes, iters)
      val key = (gen.generateDerivedParameters(bits)) as KeyParameter
      return Base64.encodeToString(key.key, Base64.NO_WRAP)
    }
  }

  @JvmStatic
  fun digestBytes(algo: String, data: ByteArray): ByteArray {
    if (NativeSeaModule.useNativeCrypto) {
      try {
        val out = nativeDigest(algo, data)
        if (out != null) return out
        throw IllegalStateException("nativeDigest returned null for algorithm: $algo")
      } catch (e: Throwable) {
        throw RuntimeException("nativeDigest failed for algorithm: $algo", e)
      }
    } else {
      return runJavaDigest(algo, data)
    }
  }

  @JvmStatic
  fun digestString(algo: String, data: String): ByteArray {
    val bytes = data.toByteArray()
    return digestBytes(algo, bytes)
  }

  private fun runJavaDigest(algo: String, data: ByteArray): ByteArray {
    val md = MessageDigest.getInstance(algo)
    md.update(data)
    return md.digest()
  }
}
