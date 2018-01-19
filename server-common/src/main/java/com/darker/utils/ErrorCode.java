package com.darker.utils;

public enum ErrorCode {
    INVALID_RSA_GEN_PAIRKEY(5001, "生成公私钥失败"),
    INVALID_RSA_READ_PUBLIC_KEY(5002, "读取公钥失败"),
    INVALID_RSA_READ_PRIVATE_KEY(5003, "读取私钥失败"),
    ;

    int code;
    String msg;

    ErrorCode(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }
}
