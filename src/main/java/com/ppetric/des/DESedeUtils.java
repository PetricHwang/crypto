package com.ppetric.des;

import org.apache.commons.codec.DecoderException;
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

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

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
            cipher.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            // TODO add log
        }
        return out;
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
            cipher.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            // TODO add log
        }
        return out;
    }

    public static void main(String[] args) throws DecoderException {
        String key = Hex.encodeHexString(DESedeUtils.generateKey());
        System.out.println(Base64.encodeBase64String(Hex.decodeHex(key)));

        byte[] pass = Hex.decodeHex(key);
        byte[] data = "快递单sdfsdfh1213世界sfsdf".getBytes(StandardCharsets.UTF_8);

        byte[] encrypt = cryptECB(true, pass, data);
        System.out.println(Base64.encodeBase64String(encrypt));
        System.out.println(Hex.encodeHexString(encrypt));

        byte[] decrypt = cryptECB(false, pass, encrypt);
        System.out.println(new String(decrypt, StandardCharsets.UTF_8).replaceAll("\\u0000+$", ""));


        String keyHex = "9DEFDC769999625AA5961E2D91E09999";
        byte[] iv = Hex.decodeHex("0000000000000000");

        byte[] encResult = cryptCBC(true, Hex.decodeHex(keyHex), iv, "1".getBytes());
        System.out.println(Base64.encodeBase64String(encResult)); // RWvqowLoz78=
        byte[] decResult = cryptCBC(false, Hex.decodeHex(keyHex), iv, encResult);
        System.out.println(new String(decResult)); // 1
    }

}
