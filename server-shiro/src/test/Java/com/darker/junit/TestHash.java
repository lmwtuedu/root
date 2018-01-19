package com.darker.junit;

import com.darker.utils.RSA1024Utils;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.junit.Test;
import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class TestHash {

    @Test
    public void testHash256(){
        String username = "root";
        String password = "123456";
        String hash = new Sha256Hash(username + password).toHex();
        System.out.println(hash);
    }

    @Test
    public void testRSA() throws Exception {
        String data = "zhangsan";

        KeyPair keyPair=genKeyPair(1024);

        //获取公钥，并以base64格式打印出来
        PublicKey publicKey=keyPair.getPublic();
        System.out.println("公钥："+new String(Base64.getEncoder().encode(publicKey.getEncoded())));

        //获取私钥，并以base64格式打印出来
        PrivateKey privateKey=keyPair.getPrivate();
        System.out.println("私钥："+new String(Base64.getEncoder().encode(privateKey.getEncoded())));

        //公钥加密
        byte[] encryptedBytes=encrypt(data.getBytes(), publicKey);
        System.out.println("加密后："+new String(encryptedBytes));

        //私钥解密
        byte[] decryptedBytes=decrypt(encryptedBytes, privateKey);
        System.out.println("解密后："+new String(decryptedBytes));
    }



    //生成密钥对
    public static KeyPair genKeyPair(int length) throws Exception{
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

    @Test
    public void testDecData() throws Exception{
        String privKeyBase64 = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIwuGciVb0eFUS3eov6HEy1aEDFVjE/URNQPJ8Cvlz9/dyyLwBKw5SBufQ/Hkw54pftgB5Res9H8NpJ+OBSAWKJEr/J02MmFW47zauqBVUJU0bsppz9XqwG10FKetN/GmZ2dejZG1jFzpflU1URPEXSyB2IzDb/LS5wE7ohV71P1AgMBAAECgYA2PLwTJOZ6aLXBJqwwCPk9ieRMAkqYtIuw9PAvmIDPu7TTknrNgI4Wn0laKqDWb43hFgW4vW+b5pcC1T1DiWlBQ6XpJPmQt3ob06TaDId1cLG3tLr+orA4hJ0wi5t4aHGIx2862Wkr5XUVmUc/LBwhk0sfEh6aEA7aiYbLV4egQQJBANh79EigaN/u2zz7ioRjKSXtFF29Oakf79O/ZbArE7nlVOizehowPJIsTlGYR/vg+L76wIChtRxnQSMJJkJsB+UCQQClxIwM9NRVejzJRvG6Rx2dG5bKRYRbfxLsszG3fEx9Wqal73Lcsvy4CDXjIpIFuJREF3X1ml6iKXmj/Cu09zrRAkB1lq7UHD2bFVUExOUyj+Iz9ZkQac4+LVjJvbbwgBWQ7h6233Y9b2IXS/WmoH7JNCQpKG8T78I+kV9yNnAPuDp5AkBo/e0Kg8M9BHgdr96I8mQSTxgZsyAa54hv/StfIM49kz372YZxvLgOQ70FyK6eCwN1gTqIPab0pLpTn/N64iARAkACPqXbQlLryzIXkOeB1z65NKfoXnkJC4TZKrwfrdE8YLhS95DbUSHwZ72MxyeFvH1Bd3tNvUCQEhwIQhmLH7zy";
        String encData = "MFNuQnzCIwuCkYisfk6+m6bxchNMWpa0cSr8cI6RvNGTjykoCs9pdzWjp7YGQKcBS2W27snhfKK/ePIL29b0rf9Am27usnTJL5sWLJVQkRjoZnnCxKwipVLAvoVHGJJ1RrsbYV3GgiPKmIg0H5kmXoG7i7RTh9fbSrl6Mtpoi8c=";

        BASE64Decoder base64Decoder= new BASE64Decoder();
        byte[] buffer= base64Decoder.decodeBuffer(privKeyBase64);
        PrivateKey privateKey= RSA1024Utils.byteToPrivateKey(buffer);

        byte[] content = org.apache.shiro.codec.Base64.decode(encData);
        byte[] data = decrypt(content, privateKey);
        System.out.println(new String(data));
    }

    @Test
    public void testGenPairKey() throws Exception {
        KeyPair keyPair = RSA1024Utils.genKeyPair();
        byte[] publicKey = RSA1024Utils.getPublicKey(keyPair);
        byte[] privateKey = RSA1024Utils.getPrivateKey(keyPair);
        System.out.println("public : " + org.apache.shiro.codec.Base64.encodeToString(publicKey));
        System.out.println("private : " + org.apache.shiro.codec.Base64.encodeToString(privateKey));
        RSA1024Utils.saveFileKey("./public", publicKey);
        RSA1024Utils.saveFileKey("./private", privateKey);
    }

    @Test
    public void testReadFile() throws  Exception{
        byte[] publicKey = RSA1024Utils.readFileKey("./public.key");
        byte[] privateKey = RSA1024Utils.readFileKey("./private.key");
        System.out.println("public : " + org.apache.shiro.codec.Base64.encodeToString(publicKey));
        System.out.println("private : " + org.apache.shiro.codec.Base64.encodeToString(privateKey));

    }

}
