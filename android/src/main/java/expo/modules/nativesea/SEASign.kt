package expo.modules.nativesea

import android.util.Base64
import org.spongycastle.asn1.ASN1EncodableVector
import org.spongycastle.asn1.ASN1Integer
import org.spongycastle.asn1.ASN1OutputStream
import org.spongycastle.asn1.ASN1Primitive
import org.spongycastle.asn1.ASN1Sequence
import org.spongycastle.asn1.DERSequence
import org.spongycastle.util.Arrays
import org.spongycastle.util.BigIntegers
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.spec.*

object SEASign {
  init {
    try {
      System.loadLibrary("native_sea")
    } catch (e: UnsatisfiedLinkError) {
      // library may not be available during some IDE tasks - fall back to Java
    }
  }

  @JvmStatic
  private external fun nativeSign(privKeyB64Url: String, data: ByteArray?): ByteArray?

  @JvmStatic
  private external fun nativeVerify(pubKeyXYB64Url: String, data: ByteArray?, sigRS: ByteArray?): Boolean

  @JvmStatic
  fun encodeRS(sigBlob: ByteArray): ByteArray {
    val r = BigInteger(1, Arrays.copyOfRange(sigBlob, 0, 32)).toByteArray()
    val s = BigInteger(1, Arrays.copyOfRange(sigBlob, 32, sigBlob.size)).toByteArray()
    val vector = ASN1EncodableVector()
    vector.add(ASN1Integer(r))
    vector.add(ASN1Integer(s))
    val baos = ByteArrayOutputStream()
    val asnOS = ASN1OutputStream(baos)
    asnOS.writeObject(DERSequence(vector))
    asnOS.flush()
    return baos.toByteArray()
  }

  @JvmStatic
  fun decodeRS(sigBlob: ByteArray): ByteArray {
    val asn = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(sigBlob))
    val r_bi = (asn.getObjectAt(0) as ASN1Integer).value
    val s_bi = (asn.getObjectAt(1) as ASN1Integer).value
    val r = BigIntegers.asUnsignedByteArray(r_bi)
    val s = BigIntegers.asUnsignedByteArray(s_bi)
    return Arrays.concatenate(r, s)
  }

  @JvmStatic
  fun sign(_privKey: String, strByte: ByteArray): String {
    if (NativeSeaModule.useNativeCrypto) {
      try {
        val out = nativeSign(_privKey, strByte)
        if (out != null) return Base64.encodeToString(out, Base64.NO_WRAP)
        throw IllegalStateException("nativeSign returned null")
      } catch (e: Throwable) {
        throw RuntimeException("nativeSign failed", e)
      }
    } else {
      val priv = importKey("secp256r1", _privKey, true) as PrivateKey
      // SEA passes a SHA-256 digest; sign the digest directly (no additional hashing).
      val ecdsa = Signature.getInstance("NONEwithECDSA", "SC")
      ecdsa.initSign(priv)
      ecdsa.update(strByte)
      val signature = ecdsa.sign()
      val rs = decodeRS(signature)
      return Base64.encodeToString(rs, Base64.NO_WRAP)
    }
  }

  @JvmStatic
  fun verify(_pubKey: String, strByte: ByteArray, _sigRS: String): Boolean {
    val pubClean = _pubKey.replace("\\.", ".")
    val sigRS = Base64.decode(_sigRS, Base64.NO_WRAP)

    if (NativeSeaModule.useNativeCrypto) {
      try {
        return nativeVerify(pubClean, strByte, sigRS)
      } catch (e: Throwable) {
        throw RuntimeException("nativeVerify failed", e)
      }
    } else {
      val pub = importKey("secp256r1", pubClean, false) as PublicKey
      // SEA passes a SHA-256 digest; verify the digest directly (no additional hashing).
      val ecdsaVerify = Signature.getInstance("NONEwithECDSA", "SC")
      ecdsaVerify.initVerify(pub)
      ecdsaVerify.update(strByte)
      return ecdsaVerify.verify(encodeRS(sigRS))
    }
  }

  @JvmStatic
  fun importKey(curve: String, inputKey: String, isPrivate: Boolean): Key {
    val parameters = AlgorithmParameters.getInstance("EC", "SC")
    parameters.init(ECGenParameterSpec(curve))
    val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
    val kf = KeyFactory.getInstance("EC", "SC")
    return if (isPrivate) {
      val privateKeyS = Base64.decode(inputKey, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
      val privateSpec = ECPrivateKeySpec(BigIntegers.fromUnsignedByteArray(privateKeyS), ecParameters)
      kf.generatePrivate(privateSpec)
    } else {
      // split on literal dot (.) between X and Y components
      val xy = inputKey.split("\\.".toRegex())
      if (xy.size < 2) {
        throw IllegalArgumentException("Invalid public key format, expected 'X.Y' parts but got: '$inputKey'")
      }
      val publicKeyX = Base64.decode(xy[0], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
      val publicKeyY = Base64.decode(xy[1], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
      
      val pubPoint = java.security.spec.ECPoint(BigIntegers.fromUnsignedByteArray(publicKeyX), BigIntegers.fromUnsignedByteArray(publicKeyY))
      val pubSpec = ECPublicKeySpec(pubPoint, ecParameters)
      kf.generatePublic(pubSpec)
    }
  }
}
