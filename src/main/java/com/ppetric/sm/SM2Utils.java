package com.ppetric.sm;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SM2Utils {
//    private static final Logger logger = LoggerFactory.getLogger(SM2Utils.class);

    private SM2Utils() {
    }

    /**
     * 生成SM2公私钥对
     *
     * @return Sm2KeyPair
     */
    public static SM2KeyPair generateKeyPair() {
        SM2 sm2 = SM2.Instance();
        AsymmetricCipherKeyPair keyPair = sm2.keyPairGenerator.generateKeyPair();
        ECPrivateKeyParameters ecPriv = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters ecPub = (ECPublicKeyParameters) keyPair.getPublic();

        byte[] priKey = new byte[32];
        byte[] pubKey = new byte[64];

        byte[] d = ecPriv.getD().toByteArray();
        byte[] q = ecPub.getQ().getEncoded(false);

        System.arraycopy(d, d[0] == 0x00 ? 1 : 0, priKey, 0, 32);
        System.arraycopy(q, 1, pubKey, 0, 64);

        return new SM2KeyPair(priKey, pubKey);
    }

    /**
     * 签名
     *
     * @param priKey 私钥
     * @param data   签名数据
     * @return
     */
    public static byte[] sign(byte[] priKey, byte[] data) {
        return sign(SM2Constant.USER_ID, priKey, data);
    }

    /**
     * 签名
     *
     * @param userId
     * @param priKey 私钥
     * @param data   签名数据
     * @return
     */
    public static byte[] sign(byte[] userId, byte[] priKey, byte[] data) {

        SM2 sm2 = SM2.Instance();
        BigInteger privateKey = new BigInteger(1, priKey);
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKey, sm2.domainParams);

        SM2Signer signer = new SM2Signer();
        signer.init(true,
                new ParametersWithID(new ParametersWithRandom(privateKeyParameters, new SecureRandom()),
                        userId));

        signer.update(data, 0, data.length);
        try {
            byte[] sign = signer.generateSignature();
            return derDecode(sign);
        } catch (CryptoException e) {
//            logger.error("[Sm2Utils][sign] CryptoException, ex={}", e.getMessage());
        } catch (IOException e) {
//            logger.error("[Sm2Utils][sign] IOException, ex={}", e.getMessage());
        }
        return new byte[0];
    }

    /**
     * 验签
     *
     * @param pubKey 公钥
     * @param data   数据
     * @param sign   签名
     * @return
     */
    public static boolean verify(byte[] pubKey, byte[] data, byte[] sign) {
        return verify(SM2Constant.USER_ID, pubKey, data, sign);
    }

    /**
     * 验签
     *
     * @param userId
     * @param pubKey 公钥
     * @param data   数据
     * @param sign   签名
     * @return
     */
    public static boolean verify(byte[] userId, byte[] pubKey, byte[] data, byte[] sign) {

        byte[] formatPubKey;
        if (pubKey.length == 64) {
            //添加一字节标识，用于ECPoint解析
            formatPubKey = new byte[65];
            formatPubKey[0] = 0x04;
            System.arraycopy(pubKey, 0, formatPubKey, 1, pubKey.length);
        } else {
            formatPubKey = pubKey;
        }

        SM2 sm2 = SM2.Instance();
        ECPoint pukPoint = sm2.curve.decodePoint(formatPubKey);
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, sm2.domainParams);

        SM2Signer signer = new SM2Signer();
        signer.init(false, new ParametersWithID(publicKeyParameters, userId));
        signer.update(data, 0, data.length);
        try {
            return signer.verifySignature(derEncode(sign));
        } catch (IOException e) {
//            logger.error("[Sm2Utils][verify] IOException, ex={}", e.getMessage());
        }
        return false;

    }

    /**
     * 加密
     *
     * @param pubKey 公钥
     * @param data   数据
     * @return
     */
    public static byte[] encrypt(byte[] pubKey, byte[] data) {
        byte[] formatPubKey;
        if (pubKey.length == 64) {
            //添加一字节标识，用于ECPoint解析
            formatPubKey = new byte[65];
            formatPubKey[0] = 0x04;
            System.arraycopy(pubKey, 0, formatPubKey, 1, pubKey.length);
        } else {
            formatPubKey = pubKey;
        }

        SM2 sm2 = SM2.Instance();
        ECPoint pukPoint = sm2.curve.decodePoint(formatPubKey);
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, sm2.domainParams);

        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        try {
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (InvalidCipherTextException e) {
//            logger.error("[Sm2Utils][encrypt] InvalidCipherTextException, ex={}", e.getMessage());
        }
        return new byte[0];
    }

    /**
     * 解密
     *
     * @param priKey 私钥
     * @param cipher 密文
     * @return
     */
    public static byte[] decrypt(byte[] priKey, byte[] cipher) {

        SM2 sm2 = SM2.Instance();
        BigInteger privateKey = new BigInteger(1, priKey);
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKey, sm2.domainParams);

        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, privateKeyParameters);
        try {
            return sm2Engine.processBlock(cipher, 0, cipher.length);
        } catch (InvalidCipherTextException e) {
//            logger.error("[Sm2Utils][decrypt] InvalidCipherTextException, ex={}", e.getMessage());
        }
        return new byte[0];
    }

    private static byte[] derDecode(byte[] encoding) throws IOException {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoding));
        if (seq.size() != 2) {
            return null;
        }

        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();

        byte[] rArray = r.toByteArray();
        byte[] sArray = s.toByteArray();

        byte[] btR = arrayCopyDestPos(rArray, 32);
        byte[] btS = arrayCopyDestPos(sArray, 32);

        byte[] btRS = new byte[btR.length + btS.length];
        System.arraycopy(btR, 0, btRS, 0, btR.length);
        System.arraycopy(btS, 0, btRS, btR.length, btS.length);

        return btRS;
    }

    private static byte[] derEncode(byte[] decoding) throws IOException {
        byte[] rArray = new byte[32];
        byte[] sArray = new byte[32];
        System.arraycopy(decoding, 0, rArray, 0, decoding.length / 2);
        System.arraycopy(decoding, rArray.length, sArray, 0, decoding.length - rArray.length);

        BigInteger r = new BigInteger(1, rArray);
        BigInteger s = new BigInteger(1, sArray);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    /**
     * 字节数组拷贝，返回指定长度的字节数组
     *
     * @param src
     * @param length 长度
     * @return
     */
    private static byte[] arrayCopyDestPos(byte[] src, int length) {
        byte[] result = new byte[length];

        if (src.length < length) {
            System.arraycopy(src, 0, result, length - src.length, src.length);
        } else if (src[0] == 0x00 && src.length != length) {
            System.arraycopy(src, 1, result, 0, result.length);
        } else {
            System.arraycopy(src, 0, result, 0, result.length);
        }
        return result;
    }

    private static boolean verifyEcSign(String pubKey, String data, String sign) {
        byte[] pubKeyArray = Base64.decodeBase64(pubKey);
        byte[] dataArray = Base64.decodeBase64(data);
        byte[] signArray = Base64.decodeBase64(sign);
        return SM2Utils.verify(pubKeyArray, dataArray, signArray);
    }

    public static void main(String[] args) throws DecoderException {

       /* System.out.println();

        byte[] pub = Base64.decodeBase64
                ("pZaaOWmE26VxSbIYLvUaXO0ezlRZpjjB9pJnQOVJrzBZTvX5FJOxU2Rz5Ya1bgAD+DAQ8MSudXtdq4dPz+lhUg==");


        byte[] data = Base64.decodeBase64
                ("Az4QlwYvY0BWcLaSIXL2A7+72irGQs0VXNlMVW1+nh//SDTOb2hU9uqUqh5YaYbht5SB4n61gXL+9x8n4jN4wg==");


        byte[] sign = Base64.decodeBase64
                ("KwYVrElOsuiohDvbe8UvApR6qkhYCzrhWbkVYIbGlcaBD9M3l81Y2ze4K39kcrhRyb2Dhpvyxm57yNof0bkHHQ==");

        boolean verify = verify(pub, data, sign);
        System.out.println("ver" + verify);*/


        /*SM2KeyPair sm2KeyPair = generateKeyPair();
        String priKey = Hex.encodeHexString(sm2KeyPair.getPriKey());
        String pubKey = Hex.encodeHexString(sm2KeyPair.getPubKey());
        System.out.println("prikey===="+priKey.toUpperCase());
        System.out.println("pubKey===="+pubKey.toUpperCase());*/


        String priHex = "580e20b99fbbc8f925e5effbdbad67ddf83bc57a28c48d9683dd12559a0146bc";
        String pubHex =
                "F902B73D8BBC134AC70B72733C6D9C0C2E0FA691758825D80D0CE9305D8BC3DE9819E4C4B9D248687FD419374B222FFD9B40221ACF26C18D0DFA6FFBE356F97E";


        String data = "23423423peri黄佳鹏";
        for (int i = 0; i < 100; i++) {
            byte[] sign = sign(Hex.decodeHex(priHex), data.getBytes());

            boolean verify = verify(Hex.decodeHex(pubHex), data.getBytes(), sign);


            System.out.println(verify);

            byte[] encrypt = encrypt(Hex.decodeHex(pubHex), data.getBytes());
            byte[] decrypt = decrypt(Hex.decodeHex(priHex), encrypt);
            System.out.println(new String(decrypt));
        }


    }
}