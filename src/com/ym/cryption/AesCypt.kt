package com.ym.cryption

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * AES加密
 */
object AesCypt {
    fun encrypt(input: String, psw: String): String {
        //1.创建copher对象
        val cipher = Cipher.getInstance("AES")
        //2.初始化cipher
        //通过秘钥工厂生成秘钥
        val keySpec:SecretKeySpec = SecretKeySpec(psw.toByteArray(),"AES")
        cipher.init(Cipher.ENCRYPT_MODE,keySpec)
        //3.加密/解密
        val result = cipher.doFinal(input.toByteArray())
        return Base64.encode(result)
    }


    /**
     * 解密
     */
    fun decrypt(input: String, psw: String): String {
        //1.创建cipher对象
        val c = Cipher.getInstance("AES")
        //2.初始化cipher(参数1：加密/解密模式)
        val keySpec:SecretKeySpec = SecretKeySpec(psw.toByteArray(),"AES")
        c.init(Cipher.DECRYPT_MODE, keySpec)
        //3.加密/解密
        val encrypt = c.doFinal(Base64.decode(input))
        return String(encrypt)
    }
}
fun main(){
    val psw = "1234567812345678"//秘钥，长度16位
    val input = "黑马"
    /*//1.创建copher对象
    val cipher = Cipher.getInstance("AES")
    //2.初始化cipher
    //通过秘钥工厂生成秘钥
    val keySpec:SecretKeySpec = SecretKeySpec(psw.toByteArray(),"AES")
    cipher.init(Cipher.ENCRYPT_MODE,keySpec)
    //3.加密/解密
    val result = cipher.doFinal(input.toByteArray())*/
    //AES/CBC/NoPadding (128) :16个字节，16 * 8 = 128 位
    val encrypt = AesCypt.encrypt(input,psw)
    println(encrypt)
    val decrypt = AesCypt.decrypt(encrypt,psw)
    println(decrypt)
}