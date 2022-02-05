package io.github.fungrim.bouncycastle.kms.signer;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.Digest;
import com.google.common.base.Preconditions;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import io.github.fungrim.bouncycastle.kms.client.KmsServiceClient;
import io.github.fungrim.bouncycastle.kms.util.Algorithms;
import io.github.fungrim.bouncycastle.kms.util.JcaDigest;

public class KmsContentSigner implements ContentSigner {

    private final KmsServiceClient client;

    private final ByteArrayOutputStream baout = new ByteArrayOutputStream();

    private final CryptoKeyVersionName keyName;
    private final CryptoKeyVersionAlgorithm algorithm; 

    public KmsContentSigner(KmsServiceClient client, CryptoKeyVersionName keyName, CryptoKeyVersionAlgorithm algorithm) {
        this.client = Preconditions.checkNotNull(client);
        this.keyName = Preconditions.checkNotNull(keyName);
        this.algorithm = Preconditions.checkNotNull(algorithm);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return Algorithms.toIdentifier(algorithm);
    }

    @Override
    public OutputStream getOutputStream() {
        return baout;
    }

    @Override
    public byte[] getSignature() {
        byte[] bytes = baout.toByteArray();
        Digest digest = JcaDigest.of(algorithm).digestAndWrap(bytes);
        return client.asymmetricSign(keyName, digest);
    }
}
