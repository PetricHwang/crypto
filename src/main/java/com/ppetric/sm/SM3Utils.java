package com.ppetric.sm;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class SM3Utils {
    private SM3Utils() {
    }

    public static byte[] doFinal(byte[] data) {
        SM3Digest sm3 = new SM3Digest();
        sm3.update(data, 0, data.length);
        byte[] result = new byte[sm3.getDigestSize()];
        sm3.doFinal(result, 0);
        return result;
    }

    public static byte[] hmac(byte[] data, byte[] key) {
        KeyParameter keyParameter = new KeyParameter(key);
        SM3Digest sm3 = new SM3Digest();
        HMac mac = new HMac(sm3);
        mac.init(keyParameter);
        mac.update(data, 0, data.length);
        byte[] result = new byte[mac.getMacSize()];
        mac.doFinal(result, 0);
        return result;
    }

}