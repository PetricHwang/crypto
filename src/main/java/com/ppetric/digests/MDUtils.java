package com.ppetric.digests;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;

public class MDUtils {

    public static byte[] MD5(byte[] data) {
        Digest digest = new MD5Digest();
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }
}
