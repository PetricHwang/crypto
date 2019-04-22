package com.ppetric.digests;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class SHAUtils {

    public static byte[] SHA1(byte[] data) {
        Digest digest = new SHA1Digest();
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    public static byte[] hmacSHA1(byte[] key, byte[] data) {
        KeyParameter keyParameter = new KeyParameter(key);
        Digest digest = new SHA1Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        mac.update(data, 0, data.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

}
