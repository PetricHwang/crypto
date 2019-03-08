package com.ppetric.md;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;

public class MDUtils {

    public static byte[] MD5(byte[] data) {
        Digest digest = new MD5Digest();
        digest.update(data, 0, data.length);
        byte[] md5Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(md5Bytes, 0);
        return md5Bytes;
    }
}
