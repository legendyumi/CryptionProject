package com.ym.cryption

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.FileReader
import java.io.FileWriter

/**
 * 对称加密应用场景
 */
class CryptPro {
}

fun main() {
    val key = "1234567812345678"
    //数据缓存到本地，加密
//    val json = FrequencyAnalysis().file2String("a.json")
//    val json ="1233333"
//    println(json)
//    val br = BufferedWriter(FileWriter("UserInfo.db"))
//    val encrypt = AesCypt.encrypt(json, key)
//    br.write(encrypt)
//    br.close()
    //显示，解密
    val br = BufferedReader(FileReader("UserInfo.db"))
    val readLine = br.readLine()
    println(AesCypt.decrypt(readLine,key))
}