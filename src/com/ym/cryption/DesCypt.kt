package com.ym.cryption

import java.security.Key
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec


/**
 * DES加密解密
 */
object DesCypt {
    //算法/工作模式/填充模式
//    val transformation = "DES/ECB/PKCS5Padding"
    val transformation = "DES/CBC/PKCS5Padding"

    /**
     * 加密
     */
    fun encrypt(input: String, psw: String): String {
        //1.创建cipher对象
        val c = Cipher.getInstance(transformation)
        //2.初始化cipher
        val kf = SecretKeyFactory.getInstance("DES")
        //自己制定的密钥
        val keySpec = DESKeySpec(psw.toByteArray())
        val key: Key = kf.generateSecret(keySpec)
        val iv = IvParameterSpec(psw.toByteArray())
        c.init(Cipher.ENCRYPT_MODE, key,iv)// CBC模式需要额外参数
        //3.加密/解密
        val encrypt = c.doFinal(input.toByteArray())
        return Base64.encode(encrypt)
    }

    /**
     * 解密
     */
    fun decrypt(input: String, psw: String): ByteArray {
        //1.创建cipher对象
        val c = Cipher.getInstance(transformation)
        //2.初始化cipher(参数1：加密/解密模式)
        val kf = SecretKeyFactory.getInstance("DES")
        //自己制定的密钥
        val keySpec = DESKeySpec(psw.toByteArray())
        val key: Key = kf.generateSecret(keySpec)
        val iv = IvParameterSpec(psw.toByteArray())
        c.init(Cipher.DECRYPT_MODE, key,iv)
        //3.加密/解密
//        val encrypt = c.doFinal(input.toByteArray())
        val encrypt = c.doFinal(Base64.decode(input))
        return encrypt
    }
}

fun main() {
    //原文
    val input = "黑马"
    //密钥，des长度8
    val password = "12345678"

//    val array = input.toByteArray()
//    array.forEach {
//        println(it)
//    }
    /*//1.创建cipher对象
    val c = Cipher.getInstance("DES")
    //2.初始化cipher
    val kf = SecretKeyFactory.getInstance("DES")
    //自己制定的密钥
    val keySpec = DESKeySpec(password.toByteArray())
    val key: Key = kf.generateSecret(keySpec)
    c.init(Cipher.ENCRYPT_MODE, key)
    //3.加密/解密
    val encrypt = c.doFinal(input.toByteArray())*/
    //DES/CBC/NoPadding (56) -> 56:8个字节 ，8*8 = 64位，DES前7位参与加密计算，最后一位作为校验码
    val encrypt = DesCypt.encrypt(input, password);
    println("加密=$encrypt")//加密后乱码  1个中文3个字符，加密后长度变了+2
    val decrypt = DesCypt.decrypt(encrypt, password)
    println("解密=${String(decrypt)}")
}