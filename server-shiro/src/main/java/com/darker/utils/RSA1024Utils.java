package com.darker.utils;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSA1024Utils {

    //生成密钥对
    public static KeyPair genKeyPair() throws Exception{
        KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    //公钥加密
    public static byte[] encrypt(byte[] content, PublicKey publicKey) throws Exception{
        Cipher cipher=Cipher.getInstance("RSA");//java默认"RSA"="RSA/ECB/PKCS1Padding"
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }

    //私钥解密
    public static byte[] decrypt(byte[] content, PrivateKey privateKey) throws Exception{
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(content);
    }

    // 获取公钥
    public static byte[] getPublicKey(KeyPair keyPair)throws Exception{
        return keyPair.getPublic().getEncoded();
    }

    // 获取私钥
    public static byte[] getPrivateKey(KeyPair keyPair)throws Exception{
        return keyPair.getPrivate().getEncoded();
    }

    // 设置RSA公钥
    public static RSAPublicKey byteToPublicKey(byte[] publicKey)throws Exception{
        KeyFactory keyFactory= KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec= new X509EncodedKeySpec(publicKey);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    // 设置RSA私钥
    public static RSAPrivateKey byteToPrivateKey(byte[] privateKey) throws Exception{
        PKCS8EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory= KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    // SavePublicKeyFile
    public static void saveFileKey(String filePath, byte[] data) throws Exception{
        FileOutputStream fos = new FileOutputStream(filePath);
        fos.write(data);
        fos.flush();
        fos.close();
    }

    public static byte[] readFileKey(String filePath) throws Exception{
        File file = new File(filePath);
        FileInputStream fileInputStream = new FileInputStream(file);

        byte[] buffer = new byte[fileInputStream.available()];
        fileInputStream.read(buffer);
        fileInputStream.close();

        return buffer;

    }
}
