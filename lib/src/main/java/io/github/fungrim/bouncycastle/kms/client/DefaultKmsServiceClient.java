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
package io.github.fungrim.bouncycastle.kms.client;


import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.common.base.Preconditions;

public class DefaultKmsServiceClient implements KmsServiceClient {

    private final KeyManagementServiceClient client;

    public DefaultKmsServiceClient(KeyManagementServiceClient client) {
        this.client = Preconditions.checkNotNull(client);
    }

    @Override
    public CryptoKeyVersion getKey(CryptoKeyVersionName keyName) {
        return client.getCryptoKeyVersion(keyName);
    }

    @Override
    public byte[] asymmetricSign(CryptoKeyVersionName keyName, Digest digest) {
        return client.asymmetricSign(keyName, digest).getSignature().toByteArray();
    }

    @Override
    public byte[] getPublicKeyPem(CryptoKeyVersionName keyName) {
        return client.getPublicKey(keyName).getPemBytes().toByteArray();
    }
}
