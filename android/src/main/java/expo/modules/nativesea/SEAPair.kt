package expo.modules.nativesea

import android.util.Base64
import org.spongycastle.asn1.nist.NISTNamedCurves
import org.spongycastle.crypto.AsymmetricCipherKeyPair
import org.spongycastle.crypto.generators.ECKeyPairGenerator
import org.spongycastle.crypto.params.ECDomainParameters
import org.spongycastle.crypto.params.ECKeyGenerationParameters
import org.spongycastle.crypto.params.ECPrivateKeyParameters
import org.spongycastle.crypto.params.ECPublicKeyParameters
import org.spongycastle.util.BigIntegers
import org.spongycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.KeyFactory
import java.security.SecureRandom
import org.spongycastle.jce.ECNamedCurveTable
import org.spongycastle.jce.spec.ECPrivateKeySpec
import org.spongycastle.jce.spec.ECPublicKeySpec
import org.spongycastle.jce.spec.ECParameterSpec
import org.spongycastle.jce.interfaces.ECPrivateKey
import org.spongycastle.jce.interfaces.ECPublicKey

object SEAPair {
  @JvmStatic
  fun pair(): Array<String> {
    val p = NISTNamedCurves.getByName("P-256")
    val params = ECDomainParameters(p.curve, p.g, p.n, p.h)
    val random = SecureRandom()
    val pGen = ECKeyPairGenerator()
    val genParam = ECKeyGenerationParameters(params, random)
    pGen.init(genParam)
    val pair: AsymmetricCipherKeyPair = pGen.generateKeyPair()
    val priv = pair.private as ECPrivateKeyParameters
    val pub = pair.public as ECPublicKeyParameters
    val d = priv.d
    val ecPoint: ECPoint = pub.q
    val x = ecPoint.affineXCoord.toBigInteger()
    val y = ecPoint.affineYCoord.toBigInteger()
    val X = BigIntegers.asUnsignedByteArray(x)
    val Y = BigIntegers.asUnsignedByteArray(y)
    val D = BigIntegers.asUnsignedByteArray(d)
    val out = Array(2) { "" }
    out[0] = Base64.encodeToString(D, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    out[1] = Base64.encodeToString(X, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP) + "." + Base64.encodeToString(Y, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    return out
  }

  @JvmStatic
  fun fromPublic(curve: String, pub: String): ECPublicKeyParameters {
    val p = NISTNamedCurves.getByName("P-256")
    val params = ECDomainParameters(p.curve, p.g, p.n, p.h)
    // Handle escaped dots coming from JS serializations (e.g. "x\.")
    val pubClean = pub.replace("\\.", ".")
    val xy = pubClean.split('.')
    if (xy.size < 2) {
      throw IllegalArgumentException("Invalid public key format, expected 'X.Y' parts but got: '$pub'")
    }
    val X = Base64.decode(xy[0], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    val Y = Base64.decode(xy[1], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    val x = BigIntegers.fromUnsignedByteArray(X)
    val y = BigIntegers.fromUnsignedByteArray(Y)
    val Q: ECPoint = p.curve.createPoint(x, y)
    return ECPublicKeyParameters(Q, params)
  }

  @JvmStatic
  fun fromPrivate(curve: String, priv: String): ECPrivateKeyParameters {
    val p = NISTNamedCurves.getByName("P-256")
    val params = ECDomainParameters(p.curve, p.g, p.n, p.h)
    val D = Base64.decode(priv, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    val d = BigIntegers.fromUnsignedByteArray(D)
    return ECPrivateKeyParameters(d, params)
  }

  @JvmStatic
  fun publicFromPrivate(inputPrivateKey: String): String {
    val curve = "secp256r1"
    try {
      val keyFactory = KeyFactory.getInstance("EC", "SC")
      val ecSpec = ECNamedCurveTable.getParameterSpec(curve)
      val privateKeyS = Base64.decode(inputPrivateKey, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
      val privateKeySpec = ECPrivateKeySpec(BigIntegers.fromUnsignedByteArray(privateKeyS), ecSpec)
      val privateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey
      val Q = ecSpec.g.multiply(privateKey.d)
      val pubSpec = ECPublicKeySpec(Q, ecSpec)
      val publicKeyGenerated = keyFactory.generatePublic(pubSpec) as ECPublicKey
      val ecPoint = publicKeyGenerated.q
      val x = ecPoint.affineXCoord.toBigInteger()
      val y = ecPoint.affineYCoord.toBigInteger()
      val X = BigIntegers.asUnsignedByteArray(x)
      val Y = BigIntegers.asUnsignedByteArray(y)
      val out = Base64.encodeToString(X, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP) + "." + Base64.encodeToString(Y, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
      
      return out
    } catch (e: Exception) {
      throw RuntimeException(e)
    }
  }
}
