package expo.modules.nativesea

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.net.URL
import java.security.Security
import org.spongycastle.jce.provider.BouncyCastleProvider
import android.util.Log

class NativeSeaModule : Module() {
  companion object {
    @JvmField
    var useNativeCrypto: Boolean = true
    @JvmField
    var useNativeSign: Boolean = false
    init {
      try {
        if (Security.getProvider("SC") == null) {
          Security.addProvider(BouncyCastleProvider())
          Log.i("NativeSea", "SpongyCastle provider added")
        } else {
          Log.i("NativeSea", "SpongyCastle provider already present")
        }
      } catch (e: Exception) {
        Log.w("NativeSea", "Failed to add SpongyCastle provider: ${e.message}")
      }
    }
  }
  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  override fun definition() = ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('NativeSea')` in JavaScript.
    Name("NativeSea")

    // --- Native SEA bindings ---
    AsyncFunction("encrypt") { data: String, key: String, iv: String ->
      SEACrypto.encrypt_aes_gcm(data, key, iv)
    }

    AsyncFunction("decrypt") { data: String, pwd: String, iv: String, tag: String ->
      SEACrypto.decrypt_aes_gcm(data, pwd, iv, tag)
    }

    AsyncFunction("pbkdf2") { pwd: String, salt: String, iter: Int?, bitSize: Int? ->
      SEAWork.pbkdf2(pwd, salt, iter, bitSize)
    }

    // Accept salt as JS array of bytes (List<Int>)
    AsyncFunction("pbkdf2_2") { pwd: String, salt: List<Int>, iter: Int?, bitSize: Int? ->
      SEAWork.pbkdf2(pwd, salt, iter, bitSize)
    }

    AsyncFunction("randomUuid") {
      java.util.UUID.randomUUID().toString()
    }

    AsyncFunction("randomBytes") { length: Int ->
      val key = ByteArray(length)
      val rand = java.security.SecureRandom()
      rand.nextBytes(key)
      key.map { it.toInt() }
    }

    Function("randomBytesSync") { length: Int ->
      val key = ByteArray(length)
      val rand = java.security.SecureRandom()
      rand.nextBytes(key)
      key.map { it.toInt() }
    }

    AsyncFunction("sha256") { toHash: List<Int> ->
      val bytes = SEAUtil.readableListToByteArray(toHash)
      val digest = SEAWork.digestBytes("SHA-256", bytes)
      digest.map { it.toInt() }
    }

    Function("sha256Sync") { toHash: List<Int> ->
      val bytes = SEAUtil.readableListToByteArray(toHash)
      val digest = SEAWork.digestBytes("SHA-256", bytes)
      digest.map { it.toInt() }
    }

    AsyncFunction("sha256_utf8") { toHash: String ->
      val digest = SEAWork.digestString("SHA-256", toHash)
      digest.map { it.toInt() }
    }

    Function("sha256Sync_utf8") { toHash: String ->
      val digest = SEAWork.digestString("SHA-256", toHash)
      digest.map { it.toInt() }
    }

    AsyncFunction("pair") {
      val pair = SEAPair.pair()
      val epair = SEAPair.pair()
      mapOf(
        "priv" to pair[0],
        "pub" to pair[1],
        "epriv" to epair[0],
        "epub" to epair[1]
      )
    }

    AsyncFunction("publicFromPrivate") { key: String ->
      SEAPair.publicFromPrivate(key)
    }

    AsyncFunction("sign") { privKey: String, toHash: List<Int> ->
      val M = SEAUtil.readableListToByteArray(toHash)
      SEASign.sign(privKey, M)
    }

    AsyncFunction("verify") { pubKey: String, toHash: List<Int>, b64_sig: String ->
      val M = SEAUtil.readableListToByteArray(toHash)
      SEASign.verify(pubKey, M, b64_sig)
    }

    AsyncFunction("secret") { pubKey: String, privKey: String ->
      val secret = SEASecret.derive(SEAPair.fromPrivate("prime256v1", privKey), SEAPair.fromPublic("prime256v1", pubKey))
      android.util.Base64.encodeToString(secret, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
    }

    // (No native view exposed)
  }
}
