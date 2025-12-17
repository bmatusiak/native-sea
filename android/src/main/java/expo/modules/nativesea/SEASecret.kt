package expo.modules.nativesea

import org.spongycastle.crypto.BasicAgreement
import org.spongycastle.crypto.agreement.ECDHBasicAgreement
import org.spongycastle.crypto.params.ECPrivateKeyParameters
import org.spongycastle.crypto.params.ECPublicKeyParameters
import org.spongycastle.util.BigIntegers

object SEASecret {
  // native JNI for ECDH derive
  private external fun nativeDerive(privB64: String, pubXY: String): ByteArray?
  @JvmStatic
  fun derive(priKey: ECPrivateKeyParameters, pubKey: ECPublicKeyParameters): ByteArray {
    if (NativeSeaModule.useNativeCrypto) {
      try {
        // serialize private scalar and public point as existing JS-facing formats
        val D = BigIntegers.asUnsignedByteArray(priKey.d)
        val Db64 = android.util.Base64.encodeToString(D, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)

        val Q = pubKey.q
        val x = Q.affineXCoord.toBigInteger()
        val y = Q.affineYCoord.toBigInteger()
        val X = BigIntegers.asUnsignedByteArray(x)
        val Y = BigIntegers.asUnsignedByteArray(y)
        val pubStr = android.util.Base64.encodeToString(X, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP) + "." + android.util.Base64.encodeToString(Y, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)

        val out = nativeDerive(Db64, pubStr)
        if (out == null) throw RuntimeException("nativeDerive returned null")
        return out
      } catch (e: Throwable) {
        throw RuntimeException("nativeDerive failed", e)
      }
    } else {
      val keyAgree: BasicAgreement = ECDHBasicAgreement()
      keyAgree.init(priKey)
      return BigIntegers.asUnsignedByteArray(keyAgree.calculateAgreement(pubKey))
    }
  }
}
