package com.ym.cryption

import java.security.MessageDigest

/**
 * 消息摘要
 */
object MessageDigetUtil {
    /**
     * md5
     */
    fun md5(input: String): String {
        val digest = MessageDigest.getInstance("MD5")
        val result = digest.digest(input.toByteArray())
        println(result.size)

        //转成16进制
        return toHex(result)
    }

    /**
     * SHA1
     */
    fun sha1(input: String): String {
        val digest = MessageDigest.getInstance("SHA-1")
        val result = digest.digest(input.toByteArray())
        println("sha1加密后=" + result.size)
        return toHex(result)
    }

    /**
     * SHA256
     */
    fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val result = digest.digest(input.toByteArray())
        println("sha256加密后=" + result.size)
        println("sha25616进制=" + toHex(result).toByteArray().size)
        return toHex(result)
    }

    /**
     * 转成16进制
     */
    fun toHex(byteArray: ByteArray): String {
        //转成16进制
        //高阶函数
        val result = with(StringBuilder()) {
            byteArray.forEach {
                //                println(it)
                val value = it
                val hex = value.toInt() and (0XFF)
                val hexStr = Integer.toHexString(hex)
//                println(hexStr)
                if (hexStr.length == 1) {
                    append("0").append(hexStr)
                } else {
                    append(hexStr)
                }
            }
            this.toString()
            //        println(stringBuilder.toString().toByteArray().size)
        }
        return result
    }
}

fun main() {
    val input = "哈哈"
    /* val digest = MessageDigest.getInstance("MD5")
     val result = digest.digest(input.toByteArray())
     val stringBuilder = StringBuilder()
     //转成16进制
     result.forEach {
         println(it)
         val value = it
         val hex = value.toInt() and (0XFF)
         val hexStr = Integer.toHexString(hex)
         println(hexStr)
         if (hexStr.length == 1){
             stringBuilder.append("0").append(hexStr)
         }else{
             stringBuilder.append(hexStr)
         }
     }
     println(stringBuilder.toString())
     println(stringBuilder.toString().toByteArray().size)*/
    val result = MessageDigetUtil.md5(input)
    println(result)
    val sha1 = MessageDigetUtil.sha1(input)
    println(sha1)
    val sha256 = MessageDigetUtil.sha256(input)
    println(sha256)
}