package com.ym.cryption

/**
 * 凯撒加密：就是对字母进行偏移
 */
class CaesarCrypt {
    /**
     * 加密
     * @param input 原文
     * @param key 秘钥
     */
    fun encrypt(input: String, key: Int): String {
        val charArray = input.toCharArray()
        return with(StringBuffer()) {
            charArray.forEach {
                //遍历每一个字母，对ascii偏移
                val c = it
                //获取ascii
                var ascii = c.toInt()
                //移动
                ascii += key
                //转成字符
                val toChar = ascii.toChar()
                append(toChar)
            }
            toString()
        }
    }

    /**
     * 解密
     * @param input 加密的密文
     */
    fun decrypt(input: String, key: Int): String {
        val charArray = input.toCharArray()
        return with(StringBuffer()) {
            charArray.forEach {
                //遍历每一个字符，对ascii偏移
                val c = it
                //获取支付ascii
                var ascii = c.toInt()

                //反方向移动
                ascii -= key
                //转成字符
                val result = ascii.toChar()
                append(result)
            }
            //返回结果
            toString()
        }
    }
}

fun main(args: Array<String>) {
    val result = CaesarCrypt().encrypt("i love you", 1)
    println(result)
    val decrypt = CaesarCrypt().decrypt(result, 1)
    println(decrypt)
}
