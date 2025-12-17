package expo.modules.nativesea

import android.util.Base64
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object SEACrypto {
  private const val KEY_ALGORITHM = "AES"
  private const val GCM_TAG_LENGTH = 16

  // private native implementations
  private external fun nativeEncryptAesGcm(text: String, keyData: String, ivData: String): String?
  private external fun nativeDecryptAesGcm(ciphertextData: String, keyData: String, ivData: String, tagData: String): String?

  @JvmStatic
  fun encrypt_aes_gcm(text: String, keyData: String, ivData: String): String {
    if (NativeSeaModule.useNativeCrypto) {
      try {
        val out = nativeEncryptAesGcm(text, keyData, ivData)
        if (out == null) throw RuntimeException("nativeEncryptAesGcm returned null")
        return out
      } catch (e: Throwable) {
        throw RuntimeException("nativeEncryptAesGcm failed", e)
      }
    } else {
      val keyBytes = Base64.decode(keyData, Base64.NO_WRAP)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val iv = Base64.decode(ivData, Base64.NO_WRAP)
      val _text = Base64.decode(text, Base64.NO_WRAP)
      val secretKey = SecretKeySpec(keyBytes, KEY_ALGORITHM)
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH * 8, iv))
      val out = cipher.doFinal(_text)
      val outB64 = Base64.encodeToString(out, Base64.NO_WRAP)
      val outHex = out.joinToString(separator = "") { "%02x".format(it.toInt() and 0xff) }
      return outB64
    }
  }

  @JvmStatic
  fun decrypt_aes_gcm(ciphertextData: String, keyData: String, ivData: String, tagData: String): String {
    if (NativeSeaModule.useNativeCrypto) {
      try {
        val out = nativeDecryptAesGcm(ciphertextData, keyData, ivData, tagData)
        if (out == null) throw RuntimeException("nativeDecryptAesGcm returned null")
        return out
      } catch (e: Throwable) {
        throw RuntimeException("nativeDecryptAesGcm failed", e)
      }
    } else {
      val keyBytes = Base64.decode(keyData, Base64.NO_WRAP)
      val ivBytes = Base64.decode(ivData, Base64.NO_WRAP)
      val ciphertext = Base64.decode(ciphertextData, Base64.NO_WRAP)
      val tag = Base64.decode(tagData, Base64.NO_WRAP)
      // Log decoded hex for precise byte-level comparison
      val keyHex = keyBytes.joinToString(separator = "") { "%02x".format(it.toInt() and 0xff) }
      val ivHex = ivBytes.joinToString(separator = "") { "%02x".format(it.toInt() and 0xff) }
      val ctHex = ciphertext.joinToString(separator = "") { "%02x".format(it.toInt() and 0xff) }
      val tagHex = tag.joinToString(separator = "") { "%02x".format(it.toInt() and 0xff) }
      val secretKey = SecretKeySpec(keyBytes, KEY_ALGORITHM)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH * 8, ivBytes))
      // Try ciphertext||tag (typical) first
      val combined = ByteArray(ciphertext.size + tag.size)
      for (i in combined.indices) combined[i] = if (i < ciphertext.size) ciphertext[i] else tag[i - ciphertext.size]
      try {
        return String(cipher.doFinal(combined), StandardCharsets.UTF_8)
      } catch (e: Exception) {
        // first attempt failed
        // Try tag||ciphertext as a fallback (some implementations/encodings may differ)
        try {
          val altCombined = ByteArray(tag.size + ciphertext.size)
          for (i in altCombined.indices) altCombined[i] = if (i < tag.size) tag[i] else ciphertext[i - tag.size]
          return String(cipher.doFinal(altCombined), StandardCharsets.UTF_8)
        } catch (e2: Exception) {
          throw e2
        }
      }
    }
  }
}
