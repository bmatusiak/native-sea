package expo.modules.nativesea

import android.util.Base64
import org.spongycastle.crypto.Digest
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.spongycastle.crypto.params.KeyParameter
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

object SEAWork {
  @JvmStatic
  fun pbkdf2(pwd: String, salt: String, iter: Int?, bitSize: Int?): String {
    val algorithmDigest: Digest = SHA256Digest()
    val gen = PKCS5S2ParametersGenerator(algorithmDigest)
    // Accept salt as either a UTF-8 string or as a comma-separated list of numeric bytes
    if (salt.contains(",")) {
      val parts = salt.split(",").map { it.trim() }
      val bytes = ByteArray(parts.size)
      for (i in parts.indices) {
        val v = parts[i]
        if (v.isEmpty()) continue
        bytes[i] = v.toInt().toByte()
      }
      gen.init(pwd.toByteArray(StandardCharsets.UTF_8), bytes, iter ?: 1000)
    } else {
      gen.init(pwd.toByteArray(StandardCharsets.UTF_8), salt.toByteArray(StandardCharsets.UTF_8), iter ?: 1000)
    }
    val key = (gen.generateDerivedParameters((bitSize ?: 256))) as KeyParameter
    return Base64.encodeToString(key.key, Base64.NO_WRAP)
  }

  @JvmStatic
  fun pbkdf2(pwd: String, saltList: List<Int>, iter: Int?, bitSize: Int?): String {
    val algorithmDigest: Digest = SHA256Digest()
    val gen = PKCS5S2ParametersGenerator(algorithmDigest)
    val bytes = SEAUtil.readableListToByteArray(saltList)
    gen.init(pwd.toByteArray(StandardCharsets.UTF_8), bytes, iter ?: 1000)
    val key = (gen.generateDerivedParameters((bitSize ?: 256))) as KeyParameter
    return Base64.encodeToString(key.key, Base64.NO_WRAP)
  }

  @JvmStatic
  fun digestBytes(algo: String, data: ByteArray): ByteArray {
    val md = MessageDigest.getInstance(algo)
    md.update(data)
    return md.digest()
  }

  @JvmStatic
  fun digestString(algo: String, data: String): ByteArray {
    val md = MessageDigest.getInstance(algo)
    md.update(data.toByteArray())
    return md.digest()
  }
}
