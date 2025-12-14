package expo.modules.nativesea

object SEAUtil {
  fun bytesToHex(bytes: ByteArray): String {
    val hexArray = "0123456789abcdef".toCharArray()
    val hexChars = CharArray(bytes.size * 2)
    for (j in bytes.indices) {
      val v = bytes[j].toInt() and 0xFF
      hexChars[j * 2] = hexArray[v ushr 4]
      hexChars[j * 2 + 1] = hexArray[v and 0x0F]
    }
    return String(hexChars)
  }

  fun readableListToByteArray(list: List<Int>): ByteArray {
    val arr = ByteArray(list.size)
    for (i in list.indices) arr[i] = list[i].toByte()
    return arr
  }

  fun byteArrayToIntList(bytes: ByteArray): List<Int> {
    return bytes.map { it.toInt() and 0xFF }
  }
}
