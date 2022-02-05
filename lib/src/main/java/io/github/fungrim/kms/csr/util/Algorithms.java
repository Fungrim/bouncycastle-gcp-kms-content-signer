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
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

public class Algorithms {

    private Algorithms() {
    }

    public static AlgorithmIdentifier toIdentifier(CryptoKeyVersionAlgorithm algorithm) {
        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();
        switch (algorithm) {
            case EC_SIGN_P256_SHA256 :
                return finder.find("SHA256WITHECDSA");
            case EC_SIGN_P384_SHA384 :
                return finder.find("SHA384WITHECDSA");
            case RSA_SIGN_PKCS1_2048_SHA256 :
            case RSA_SIGN_PKCS1_3072_SHA256 :
            case RSA_SIGN_PKCS1_4096_SHA256 :
                return finder.find("SHA256WITHRSA");
            case RSA_SIGN_PKCS1_4096_SHA512 :
                return finder.find("SHA512WITHRSA");
            case RSA_SIGN_PSS_2048_SHA256 :
            case RSA_SIGN_PSS_3072_SHA256 :
            case RSA_SIGN_PSS_4096_SHA256 :
                return finder.find("SHA256WITHRSAANDMGF1");
            case RSA_SIGN_PSS_4096_SHA512 :
                return finder.find("SHA512WITHRSAANDMGF1");
            default :
                throw new IllegalArgumentException("Unsupported signature algorithm: " + algorithm);
        }
    }
}
