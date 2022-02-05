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
package io.github.fungrim.kms.csr;


import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.common.base.Preconditions;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import io.github.fungrim.kms.csr.client.KmsServiceClient;
import io.github.fungrim.kms.csr.util.Keys;
import java.security.PublicKey;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * This KMS key cache caches key version, version name and JCA public key for a
 * given duration.
 */
public class KmsKeyCache {

    /**
     * A key cache entry with key, key version name and JCA public key.
     */
    public static class Entry {

        private final CryptoKeyVersion key;
        private final CryptoKeyVersionName keyName;
        private final PublicKey publicKey;

        private Entry(CryptoKeyVersion key, CryptoKeyVersionName keyName, PublicKey publicKey) {
            this.key = key;
            this.keyName = keyName;
            this.publicKey = publicKey;
        }

        /**
         * @return The crypto version key, never null
         */
        public CryptoKeyVersion getKey() {
            return key;
        }

        /**
         * @return The crypto version key name, never null
         */
        public CryptoKeyVersionName getKeyName() {
            return keyName;
        }

        /**
         * @return The JCA public key, never null
         */
        public PublicKey getPublicKey() {
            return publicKey;
        }

        /**
         * @return The crypto key version algorithm, never null
         */
        public CryptoKeyVersionAlgorithm getAlgorithm() {
            return key.getAlgorithm();
        }
    }

    private final LoadingCache<CryptoKeyVersionName, Entry> entryCache;

    /**
     * Create a new KMS key cache.
     * 
     * @param cacheDuration
     *            Cache duration, must not be null
     * @param client
     *            Kms service client, must not be null
     */
    public KmsKeyCache(final Duration cacheDuration, final KmsServiceClient client) {
        Preconditions.checkNotNull(client);
        this.entryCache = CacheBuilder.newBuilder()
                .expireAfterAccess(Preconditions.checkNotNull(cacheDuration).toMillis(), TimeUnit.MILLISECONDS)
                .build(new CacheLoader<CryptoKeyVersionName, Entry>() {

                    @Override
                    public Entry load(CryptoKeyVersionName keyName) throws Exception {
                        // load the key from KMS
                        CryptoKeyVersion key = client.getKey(keyName);
                        PublicKey pk = Keys.toPublicKey(key.getAlgorithm(), client.getPublicKeyPem(keyName));
                        return new Entry(key, keyName, pk);
                    }
                });
    }

    /**
     * Get a key from the cache or fetch it from KMS. This will fail if the key
     * doesn't exist, the caller don't have rights to access the key, or if the key
     * is not a key for assymetric signing.
     * 
     * @param keyName
     *            Key to get, must not be null
     * @return A key entry
     */
    public Entry get(CryptoKeyVersionName keyName) {
        return entryCache.getUnchecked(Preconditions.checkNotNull(keyName));
    }
}
