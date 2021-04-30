package com.ym.cryption

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

/**
 * 数字签名
 */
object SignatureDemo {
    /**
     * 数字签名
     */
    fun sign(privateKey: PrivateKey, input: String): String {
        //获取数字签名实例对象
        val signature = Signature.getInstance("SHA256withRSA")
        //初始化签名
        signature.initSign(privateKey)
        //设置数据源
        signature.update(input.toByteArray())
        //签名
        val sign = Base64.encode(signature.sign())
        return sign
    }

    /**
     * 校验
     */
    fun verify(input: String, publicKey: PublicKey, sign: String): Boolean {
        val signature = Signature.getInstance("SHA256withRSA")
        //初始化签名
        signature.initVerify(publicKey)
        //传入数据源
        signature.update(input.toByteArray())
        //校验签名信息
        val verify = signature.verify(Base64.decode(sign))
        return verify
    }
}

fun main() {
    val input = "111"
    val privateKey = RSACrypt().getPrivateKey()
    val publicKey = RSACrypt().getPublicKey()
    val sign = SignatureDemo.sign(privateKey, input)
    println(sign)
    //********************校验************************
    //校验签名
    val verify = SignatureDemo.verify(input, publicKey, sign)
    println("校验=" + verify)
}