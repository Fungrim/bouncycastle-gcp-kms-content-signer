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
package io.github.fungrim.kms.csr.util;


import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class Keys {

    private Keys() {
    }

    public static PublicKey toPublicKey(CryptoKeyVersionAlgorithm algorithm, byte[] pemBytes) {
        PemReader reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(pemBytes)));
        try {
            PemObject spki = reader.readPemObject();
            if (isEc(algorithm)) {
                return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki.getContent()));
            } else if (isRsa(algorithm)) {
                return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki.getContent()));
            } else {
                throw new IllegalArgumentException("Cannot create public key for algorithm: " + algorithm);
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to create public key", e);
        }
    }

    private static boolean isEc(CryptoKeyVersionAlgorithm algorithm) {
        return algorithm.name().startsWith("EC");
    }

    private static boolean isRsa(CryptoKeyVersionAlgorithm algorithm) {
        return algorithm.name().startsWith("RSA");
    }
}
