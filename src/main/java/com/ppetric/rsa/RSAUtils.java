package com.ppetric.rsa;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

public class RSAUtils {
    private RSAUtils() {
    }

    /**
     * signSHA1WithRSA
     *
     * @param pri
     * @param data
     * @return
     */
    public static byte[] signSHA1WithRSA(byte[] pri, byte[] data) throws Exception {
        AsymmetricKeyParameter key = PrivateKeyFactory.createKey(pri);
        RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());
        signer.init(true, key);
        signer.update(data, 0, data.length);
        return signer.generateSignature();
    }
}
