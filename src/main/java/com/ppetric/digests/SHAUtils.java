package com.ppetric.digests;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

public class SHAUtils {

    public static byte[] SHA1(byte[] data) {
        Digest digest = new SHA1Digest();
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }
}
