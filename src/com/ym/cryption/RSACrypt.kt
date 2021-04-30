package com.ym.cryption

import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * 非对称加密RSA加密和解密
 */
class RSACrypt {
    val transformation = "RSA"
    val ENCRYPT_MAX_SIZE = 117//每次加密最大字节
    val DECRYPT_MAX_SIZE = 128 //解密：每次最大加密长度
    val publicKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC039jg7sotX4xr+LGdmTWs7TgRGTAiMAINpAX8B1r8qUbiyHpqp4ozlQhOI8ogMM+p1rcDWTvM+8Iwd9laClFUeVYaun+h4XUgIM5nQ1qmTVN3uf1lYZxzf2a8B0pHWxPYDwIyeHj2UEb3Cx5i5NG5cZ24depXP6jPKwyzTTJtEwIDAQAB"
    val privateKeyStr = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALTf2ODuyi1fjGv4sZ2ZNaztOBEZMCIwAg2kBfwHWvypRuLIemqnijOVCE4jyiAwz6nWtwNZO8z7wjB32VoKUVR5Vhq6f6HhdSAgzmdDWqZNU3e5/WVhnHN/ZrwHSkdbE9gPAjJ4ePZQRvcLHmLk0blxnbh16lc/qM8rDLNNMm0TAgMBAAECgYAKlYrAZtjH3O5/pvblzQBaFSuRvJKXfY2xNKbw/5EwdctjG+4l7ZXlvNPWlruONK0COEFPXdpk/Vp4sZqzbSUjHcirJp4NifP+RuJAiAYzqkVT7kPykC9+id4JPsyLmKRt7bLc30vCtdFCADlYW0/vHHxMo5bENQb1ssmWSA9QgQJBAP50eLzPGQRhzeQqcJEDEK1xNqj3bJ2sL5nKi4BpHoORoqjnJkxXOsiunkh2vOLW1Hv/rRvuSv4BPQ61qmJwnNMCQQC1+QA6WuEchcnM/kDof0HAIFJQ6iWdavoLFldSW8Jt5xoWjJ/BBEs2KGnAGFtEPzjGIM5pthqONbUbQLwKW8bBAkB8yYncroPKTly2pMmHlEU9ieQQgSbXPHYrqdU4KFU6mNV4l8OEdNLzUA934iNH66tRFFZE+Fv2rYzQBe+FT0zZAkBR9I8RuRRhkC/Oz0PUclved7AbGRlPyHpMvAcf5Iuwi8DIHxVkDNcC0Tivd0jDd+XN9cCBA676FV43o/QMhkEBAkAVQiJlcrVNJHfG3/94VV3vs8iCwcFiMn14Rij7YqhkpdaY6rEM17Wttc/jowkkJ4bk7mmDJOHWyyPLYhJq4tiV"

    /**
     * 获取私钥
     */
    fun getPrivateKey(): PrivateKey {
        //字符串转成秘钥对对象
        val kf = KeyFactory.getInstance("RSA")
        val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(Base64.decode(privateKeyStr)))
        return  privateKey
    }

    /**
     * 获取公钥
     */
    fun getPublicKey(): PublicKey {
        //字符串转成秘钥对对象
        val kf = KeyFactory.getInstance("RSA")
        val publicKey = kf.generatePublic(X509EncodedKeySpec(Base64.decode(publicKeyStr)))
        return  publicKey
    }

    /**
     * 私钥加密
     * @param input 原文
     * @param privateKey 私钥
     */
    fun encryptByPrivateKey(input: String, privateKey: PrivateKey): String {
        val byteArray = input.toByteArray()

        //***************************非对称加密三部曲*********************
        //1.创建copher对象
        val cipher = Cipher.getInstance(transformation)
        //2.初始化cipher
        cipher.init(Cipher.ENCRYPT_MODE, privateKey)
        //3.加密/解密
//        val encrypt = cipher.doFinal(input.toByteArray())

        var temp: ByteArray? = null
        var offest = 0//当前偏移的位置

        val bos = ByteArrayOutputStream()

        while (byteArray.size - offest > 0) {//没加密完
            //每次最大加密117个字节
            if (byteArray.size - offest >= ENCRYPT_MAX_SIZE) {
                //剩余部分大于117
                temp = cipher.doFinal(byteArray, offest, ENCRYPT_MAX_SIZE)
                //重新计算偏移的位置
                offest += ENCRYPT_MAX_SIZE
            }else{
                //加密最后一块
                temp = cipher.doFinal(byteArray, offest, byteArray.size - offest)
                offest+= byteArray.size
            }
            //存储到临时的缓冲区
            bos.write(temp)
        }
        bos.close()
        return Base64.encode(bos.toByteArray())
    }

    /**
     * 公钥加密
     * @param input 原文
     * @param privateKey 公钥
     */
    fun encryptByPublicKey(input: String, publicKey: PublicKey): String {
        //***************************非对称加密三部曲*********************
        val byteArray = input.toByteArray()

        //***************************非对称加密三部曲*********************
        //1.创建copher对象
        val cipher = Cipher.getInstance(transformation)
        //2.初始化cipher
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        //3.加密/解密
//        val encrypt = cipher.doFinal(input.toByteArray())

        var temp: ByteArray? = null
        var offest = 0//当前偏移的位置

        val bos = ByteArrayOutputStream()

        while (byteArray.size - offest > 0) {//没加密完
            //每次最大加密117个字节
            if (byteArray.size - offest >= ENCRYPT_MAX_SIZE) {
                //剩余部分大于117
                temp = cipher.doFinal(byteArray, offest, ENCRYPT_MAX_SIZE)
                //重新计算偏移的位置
                offest += ENCRYPT_MAX_SIZE
            }else{
                //加密最后一块
                temp = cipher.doFinal(byteArray, offest, byteArray.size - offest)
                offest+= byteArray.size
            }
            //存储到临时的缓冲区
            bos.write(temp)
        }
        bos.close()
        return Base64.encode(bos.toByteArray())
    }

    /**
     * 私钥解密
     * @param input 密文
     * @param privateKey 私钥
     */
    fun decryptByPrivateKey(input: String, privateKey: PrivateKey): String {
        val byteArray = Base64.decode(input)

        //***************************非对称加密三部曲*********************
        //1.创建copher对象
        val cipher = Cipher.getInstance(transformation)
        //2.初始化cipher
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        //3.加密/解密
//        val encrypt = cipher.doFinal(input.toByteArray())

        var temp: ByteArray? = null
        var offest = 0//当前偏移的位置

        val bos = ByteArrayOutputStream()

        while (byteArray.size - offest > 0) {//没加密完
            //每次最大解密128个字节
            if (byteArray.size - offest >= DECRYPT_MAX_SIZE) {
                //剩余部分大于117
                temp = cipher.doFinal(byteArray, offest, DECRYPT_MAX_SIZE)
                //重新计算偏移的位置
                offest += DECRYPT_MAX_SIZE
            }else{
                //加密最后一块
                temp = cipher.doFinal(byteArray, offest, byteArray.size - offest)
                offest= byteArray.size
            }
            //存储到临时的缓冲区
            bos.write(temp)
        }
        bos.close()
        return String(bos.toByteArray())
    }

    /**
     * 公钥解密
     * @param input 原文
     * @param privateKey 公钥
     */
    fun decryptByPublicKey(input: String, publicKey: PublicKey): String {
        val byteArray = Base64.decode(input)

        //***************************非对称加密三部曲*********************
        //1.创建copher对象
        val cipher = Cipher.getInstance(transformation)
        //2.初始化cipher
        cipher.init(Cipher.DECRYPT_MODE, publicKey)
        //3.加密/解密
//        val encrypt = cipher.doFinal(input.toByteArray())

        var temp: ByteArray? = null
        var offest = 0//当前偏移的位置

        val bos = ByteArrayOutputStream()

        while (byteArray.size - offest > 0) {//没加密完
            //每次最大解密128个字节
            if (byteArray.size - offest >= DECRYPT_MAX_SIZE) {
                //剩余部分大于117
                temp = cipher.doFinal(byteArray, offest, DECRYPT_MAX_SIZE)
                //重新计算偏移的位置
                offest += DECRYPT_MAX_SIZE
            }else{
                //加密最后一块
                temp = cipher.doFinal(byteArray, offest, byteArray.size - offest)
                offest= byteArray.size
            }
            //存储到临时的缓冲区
            bos.write(temp)
        }
        bos.close()
        return String(bos.toByteArray())
    }
}

fun main() {
    //如何生成密钥对
   /* val generator = KeyPairGenerator.getInstance("RSA")//密钥对生成器
    val keyPair = generator.genKeyPair()//生成密钥对
    val publicKey = keyPair.public//公钥
    val private = keyPair.private//私钥
    println("公钥${Base64.encode(publicKey.encoded)}")
    println("私钥${Base64.encode(private.encoded)}")*/
    //********************保存秘钥对********************//
    val publicKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC039jg7sotX4xr+LGdmTWs7TgRGTAiMAINpAX8B1r8qUbiyHpqp4ozlQhOI8ogMM+p1rcDWTvM+8Iwd9laClFUeVYaun+h4XUgIM5nQ1qmTVN3uf1lYZxzf2a8B0pHWxPYDwIyeHj2UEb3Cx5i5NG5cZ24depXP6jPKwyzTTJtEwIDAQAB"
    val privateKeyStr = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALTf2ODuyi1fjGv4sZ2ZNaztOBEZMCIwAg2kBfwHWvypRuLIemqnijOVCE4jyiAwz6nWtwNZO8z7wjB32VoKUVR5Vhq6f6HhdSAgzmdDWqZNU3e5/WVhnHN/ZrwHSkdbE9gPAjJ4ePZQRvcLHmLk0blxnbh16lc/qM8rDLNNMm0TAgMBAAECgYAKlYrAZtjH3O5/pvblzQBaFSuRvJKXfY2xNKbw/5EwdctjG+4l7ZXlvNPWlruONK0COEFPXdpk/Vp4sZqzbSUjHcirJp4NifP+RuJAiAYzqkVT7kPykC9+id4JPsyLmKRt7bLc30vCtdFCADlYW0/vHHxMo5bENQb1ssmWSA9QgQJBAP50eLzPGQRhzeQqcJEDEK1xNqj3bJ2sL5nKi4BpHoORoqjnJkxXOsiunkh2vOLW1Hv/rRvuSv4BPQ61qmJwnNMCQQC1+QA6WuEchcnM/kDof0HAIFJQ6iWdavoLFldSW8Jt5xoWjJ/BBEs2KGnAGFtEPzjGIM5pthqONbUbQLwKW8bBAkB8yYncroPKTly2pMmHlEU9ieQQgSbXPHYrqdU4KFU6mNV4l8OEdNLzUA934iNH66tRFFZE+Fv2rYzQBe+FT0zZAkBR9I8RuRRhkC/Oz0PUclved7AbGRlPyHpMvAcf5Iuwi8DIHxVkDNcC0Tivd0jDd+XN9cCBA676FV43o/QMhkEBAkAVQiJlcrVNJHfG3/94VV3vs8iCwcFiMn14Rij7YqhkpdaY6rEM17Wttc/jowkkJ4bk7mmDJOHWyyPLYhJq4tiV"
    //字符串转成秘钥对对象
    val kf = KeyFactory.getInstance("RSA")
    val private = kf.generatePrivate(PKCS8EncodedKeySpec(Base64.decode(privateKeyStr)))
    val publicKey = kf.generatePublic(X509EncodedKeySpec(Base64.decode(publicKeyStr)))

    val input = "黑马黑马黑马黑马黑马黑马黑马黑马黑马黑马黑马黑马黑马黑马黑马黑马马黑马黑马黑马欢迎来到黑马程序员"
    println(input.length)
    println("byte数组长度=" + input.toByteArray().size)
    //私钥加密：不能超过117个字节
    val result = RSACrypt().encryptByPrivateKey(input, private)
    println("私钥加密$result")
    val encryptByPublicKey = RSACrypt().encryptByPublicKey(input, publicKey)
    println("公钥加密=" + encryptByPublicKey)
    val rsprivate = RSACrypt().decryptByPrivateKey(encryptByPublicKey, private)
    println("私钥解密=$rsprivate")
    val decryptByPublicKey = RSACrypt().decryptByPublicKey(result, publicKey)
    println("公钥解密=" + decryptByPublicKey)
}