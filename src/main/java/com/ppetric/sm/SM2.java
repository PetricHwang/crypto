package com.ppetric.sm;

import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SM2 {

    private final BigInteger sm2_ecc_p;
    private final BigInteger sm2_ecc_a;
    private final BigInteger sm2_ecc_b;
    private final BigInteger sm2_ecc_n;
    private final BigInteger sm2_ecc_h;
    private final BigInteger sm2_ecc_gx;
    private final BigInteger sm2_ecc_gy;
    public final ECCurve curve;
    public final ECPoint g;

    public final ECDomainParameters domainParams;
    public final ECKeyPairGenerator keyPairGenerator;

    public static SM2 Instance() {
        return new SM2();
    }

    private SM2() {
        this.sm2_ecc_p = new BigInteger(SM2Constant.ECC_PARAM[0], 16);
        this.sm2_ecc_a = new BigInteger(SM2Constant.ECC_PARAM[1], 16);
        this.sm2_ecc_b = new BigInteger(SM2Constant.ECC_PARAM[2], 16);
        this.sm2_ecc_n = new BigInteger(SM2Constant.ECC_PARAM[3], 16);
        this.sm2_ecc_h = ECConstants.ONE;
        this.sm2_ecc_gx = new BigInteger(SM2Constant.ECC_PARAM[4], 16);
        this.sm2_ecc_gy = new BigInteger(SM2Constant.ECC_PARAM[5], 16);
        this.curve = new ECCurve.Fp(sm2_ecc_p, sm2_ecc_a, sm2_ecc_b, sm2_ecc_n, sm2_ecc_h);
        this.g = curve.createPoint(sm2_ecc_gx, sm2_ecc_gy);
        this.domainParams = new ECDomainParameters(curve, g, sm2_ecc_n);

        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
        this.keyPairGenerator = new ECKeyPairGenerator();
        this.keyPairGenerator.init(keyGenerationParams);
    }

}
