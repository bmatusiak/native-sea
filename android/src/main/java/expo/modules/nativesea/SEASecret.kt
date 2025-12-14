package expo.modules.nativesea

import org.spongycastle.crypto.BasicAgreement
import org.spongycastle.crypto.agreement.ECDHBasicAgreement
import org.spongycastle.crypto.params.ECPrivateKeyParameters
import org.spongycastle.crypto.params.ECPublicKeyParameters
import org.spongycastle.util.BigIntegers

object SEASecret {
  @JvmStatic
  fun derive(priKey: ECPrivateKeyParameters, pubKey: ECPublicKeyParameters): ByteArray {
    val keyAgree: BasicAgreement = ECDHBasicAgreement()
    keyAgree.init(priKey)
    return BigIntegers.asUnsignedByteArray(keyAgree.calculateAgreement(pubKey))
  }
}
