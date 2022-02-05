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
package io.github.fungrim.kms.csr.client;


import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.Digest;

/**
 * A facade for KMS service calls.
 */
public interface KmsServiceClient {

    /**
     * @param keyName
     *            Key to get, must not be null
     * @return The crypto key version, never null
     */
    public CryptoKeyVersion getKey(CryptoKeyVersionName keyName);

    /**
     * @param keyName
     *            Key to get, must not be null
     * @return The public key pem bytes, never null
     */
    public byte[] getPublicKeyPem(CryptoKeyVersionName keyName);

    /**
     * @param keyName
     *            Key to sign with, must not be null
     * @param digest
     *            The digest to sign, must not be null
     * @return The signature as bytes, never null
     */
    public byte[] asymmetricSign(CryptoKeyVersionName keyName, Digest digest);

}
