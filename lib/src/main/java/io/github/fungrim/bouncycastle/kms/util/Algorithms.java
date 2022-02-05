package io.github.fungrim.bouncycastle.kms.util;

import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

public class Algorithms {

    private Algorithms() { }

    public static AlgorithmIdentifier toIdentifier(CryptoKeyVersionAlgorithm algorithm) {
        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();
        switch(algorithm) {
            case EC_SIGN_P256_SHA256:
                return finder.find("SHA256WITHECDSA");
            case EC_SIGN_P384_SHA384:
                return finder.find("SHA384WITHECDSA");
            case RSA_SIGN_PKCS1_2048_SHA256:
            case RSA_SIGN_PKCS1_3072_SHA256:
            case RSA_SIGN_PKCS1_4096_SHA256:
                return finder.find("SHA256WITHRSA");
            case RSA_SIGN_PKCS1_4096_SHA512:
                return finder.find("SHA512WITHRSA");
            case RSA_SIGN_PSS_2048_SHA256:
            case RSA_SIGN_PSS_3072_SHA256:
            case RSA_SIGN_PSS_4096_SHA256:
                return finder.find("SHA256WITHRSAANDMGF1");
            case RSA_SIGN_PSS_4096_SHA512:
                return finder.find("SHA512WITHRSAANDMGF1");    
            default:
                throw new IllegalArgumentException("Unsupported signature algorithm: " + algorithm);
        }
    }
}
