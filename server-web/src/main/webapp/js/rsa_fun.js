
// rsa 加密密钥
function encRsa1024(data, pubKeyBase64) {
    // Encrypt with the public key...
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(pubKeyBase64);
    var encData = encrypt.encrypt(data);

    return encData;
}

// rsa 解密
function decRsa1024(data, privKeyBase64) {
    // Decrypt with the private key...
    var decrypt = new JSEncrypt();
    decrypt.setPrivateKey(privKeyBase64);
    var uncrypted = decrypt.decrypt(encrypted);
}