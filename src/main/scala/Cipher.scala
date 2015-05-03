package org.fishmacs.zwlib

import javax.crypto.{Cipher => jCipher}
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec

import javax.crypto.KeyGenerator
import java.security.SecureRandom

class PKCS7(paddingLen: Int=8) {
  def encode(src: Array[Byte]): Array[Byte] = {
    val padding = (paddingLen - (src.length % paddingLen)).asInstanceOf[Byte]
    src ++ Array.fill(padding)(padding)
  }

  def decode(src: Array[Byte]): Array[Byte] = {
    src take (src.length - src.last)
  }
}

class Cipher(algo: String, key: Array[Byte], iv: Array[Byte], mode: String="CBC") {
  var mEncrypter: jCipher = null
  var mDecrypter: jCipher = null
  var mPadder: PKCS7 = null

  def encrypt(b: Array[Byte], padding: Boolean=true, end: Boolean=true): Array[Byte] = {
    if (mEncrypter == null)
      mEncrypter = getCipher("encrypt", padding)
    var src = b
    if (padding)
      src = mPadder encode src
    if (end)
      mEncrypter.doFinal(src)
    else
      mEncrypter.update(src)
  }

  def decrypt(b: Array[Byte], padding: Boolean=true, end: Boolean=true): Array[Byte] = {
    if (mDecrypter == null)
      mDecrypter = getCipher("decrypt", padding)
    val decrypted = 
      if (end)
        mDecrypter.doFinal(b)
      else
        mDecrypter.update(b)
    if (padding)
      mPadder decode decrypted
    else
      decrypted
  }

  def end() {
    mEncrypter.doFinal(Array.fill(iv.length)(0: Byte))
  }

  def getCipher(opMode: String, padding: Boolean): jCipher = {
    val initStr = "%s/%s/NoPadding".format(algo, mode)
    val cipher = jCipher getInstance initStr
    val secretKey = new SecretKeySpec(key, algo)
    val cipherMode = opMode match {
      case "encrypt" => jCipher.ENCRYPT_MODE
      case "decrypt" => jCipher.DECRYPT_MODE
      case _ => throw new IllegalArgumentException("Unknown mode: " + opMode)
    }
    cipher.init(cipherMode, secretKey, new IvParameterSpec(iv))
    if (padding)
      mPadder = new PKCS7(algo match {
        case "AES" => 16
        case "DESede" => 8
        case _ => 8
      })
    cipher
  }
}

object Cipher {
  val algoRithms = Map("AES"->"AES", "DES3"->"DESede")

  def apply(algo: String, key: Array[Byte], iv: Array[Byte], mode: String="cbc"): Cipher =
    new Cipher(algoRithms(algo.toUpperCase), key, iv, mode.toUpperCase)
}
