package com.ppetric.des;

import com.ppetric.digests.SHAUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.SecureRandom;
import java.security.Security;

/**
 * 3DES
 */
public class DESedeUtils {

    private DESedeUtils() {
    }

    /**
     * 生成密钥
     *
     * @return
     */
    public static byte[] generateKey() {
        DESedeKeyGenerator keyGenerator = new DESedeKeyGenerator();
        KeyGenerationParameters parameters = new KeyGenerationParameters(
                new SecureRandom(),
                DESedeParameters.DES_EDE_KEY_LENGTH * 8);
        keyGenerator.init(parameters);
        return keyGenerator.generateKey();
    }

    /**
     * 加密、解密(DESede/ECB/PKCS7Padding)
     *
     * @param encrypt
     * @param key
     * @param data
     * @return
     */
    public static byte[] cryptECB(boolean encrypt, byte[] key, byte[] data) {

        DESedeEngine engine = new DESedeEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);
        cipher.init(encrypt, new DESedeParameters(key));
        byte[] out = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, out, 0);
        try {
            len += cipher.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            // TODO add log
            e.printStackTrace();
        }

        byte[] result = new byte[len];
        System.arraycopy(out, 0, result, 0, result.length);
        return result;
    }

    /**
     * 加密、解密(DESede/CBC/PKCS7Padding)
     *
     * @param encrypt
     * @param key
     * @param iv
     * @param data
     * @return
     */
    public static byte[] cryptCBC(boolean encrypt, byte[] key, byte[] iv, byte[] data) {

        iv = iv == null ? new byte[8] : iv;
        DESedeEngine engine = new DESedeEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));
        CipherParameters params = new ParametersWithIV(new DESedeParameters(key), iv);
        cipher.init(encrypt, params);

        byte[] out = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, out, 0);
        try {
            len += cipher.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            // TODO add log
            e.printStackTrace();
        }

        byte[] result = new byte[len];
        System.arraycopy(out, 0, result, 0, result.length);
        return result;
    }

    // TODO
    public static byte[] cryptECB(byte[] key, byte[] data) {
        Security.addProvider(new BouncyCastleProvider());
        DESedeKeySpec desKeySpec = null;
        try {
            desKeySpec = new DESedeKeySpec(key);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
            SecretKey convertSecretKey = factory.generateSecret(desKeySpec);
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) throws Exception {

        String keyHex = "9DEFDC769999625AA5961E2D91E09999";
        byte[] iv = Hex.decodeHex("0000000000000000");

        String data = " 1sjdjl数据库砥砺奋进242347*#($#)%^$#^ad v ";
        byte[] sha1 = SHAUtils.SHA1(data.getBytes());
        System.out.println("sha1=" + Base64.encodeBase64String(sha1));

        byte[] enc = cryptCBC(true, Hex.decodeHex(keyHex), iv, sha1);
        System.out.println("sha1 enc=" + Base64.encodeBase64String(enc));
        byte[] dec = cryptCBC(false, Hex.decodeHex(keyHex), iv, enc);
        System.out.println("sha1=" + Base64.encodeBase64String(dec));

        System.out.println("================");
        byte[] encecb = cryptECB(true, Hex.decodeHex(keyHex), sha1);
        System.out.println("sha1 enc=" + Base64.encodeBase64String(encecb));
        byte[] dececb = cryptECB(false, Hex.decodeHex(keyHex), encecb);
        System.out.println("sha1=" + Base64.encodeBase64String(dececb));
    }

}
