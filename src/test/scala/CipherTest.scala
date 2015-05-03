package org.fishmacs.zwlib.test

import org.fishmacs.zwlib.Cipher
import org.scalatest._

class CipherTest extends FlatSpec with Matchers {
  "A AES Cipher" should "encrypt/decrypt byte arrays" in {
    val bytes = ("1" * 16) getBytes "UTF8"
    val cipher = Cipher("aes", bytes, bytes)
    val plain = "abc" getBytes "UTF8"
    val secret = Array[Int](131, 104, 217, 14, 118, 60, 47, 232, 201, 51, 161, 151, 209, 115, 19, 139) map {_.asInstanceOf[Byte]}
    cipher encrypt plain should be (secret)
    cipher decrypt secret should be (plain)
  }

  "A DES3 Cipher" should "encrypt/decrypt byte arrays" in {
    val key = ("1" * 24) getBytes "UTF8"
    val iv = ("1" * 8) getBytes "UTF8"
    val cipher = Cipher("des3", key, iv)
    val plain = "abc" getBytes "UTF8"
    val secret = Array[Int](37, 148, 143, 121, 45, 77, 75, 65) map {_.asInstanceOf[Byte]}
    cipher encrypt plain should be (secret)
    cipher decrypt secret should be (plain)
  }
}
