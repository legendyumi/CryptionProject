package com.ym.cryption

/**
 * md5应用场景：用户登录
 */
class Md5Usage {
}

fun main() {
    //登录：用户的密码，必须加密，传输中，是以密文传输
    val psw = MessageDigetUtil.md5("111111")
}