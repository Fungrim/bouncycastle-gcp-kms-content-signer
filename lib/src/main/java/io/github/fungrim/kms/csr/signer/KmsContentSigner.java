/**
 * Copyright 2022 Lars J. Nilsson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.fungrim.kms.csr.signer;


import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.Digest;
import com.google.common.base.Preconditions;
import io.github.fungrim.kms.csr.client.KmsServiceClient;
import io.github.fungrim.kms.csr.util.Algorithms;
import io.github.fungrim.kms.csr.util.JcaDigest;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

/**
 * A bouncy castle content signer, using a KMS key.
 */
public class KmsContentSigner implements ContentSigner {

    private final ByteArrayOutputStream baout = new ByteArrayOutputStream();

    private final KmsServiceClient client;
    private final CryptoKeyVersionName keyName;
    private final CryptoKeyVersionAlgorithm algorithm;

    /**
     * @param client
     *            Client to use, must not be null
     * @param keyName
     *            Key to sign with, must not be null
     * @param algorithm
     *            Key algorithm, must not be null
     */
    public KmsContentSigner(KmsServiceClient client, CryptoKeyVersionName keyName,
            CryptoKeyVersionAlgorithm algorithm) {
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
