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


import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.common.base.Preconditions;
import io.github.fungrim.kms.csr.client.DefaultKmsServiceClient;
import io.github.fungrim.kms.csr.client.KmsServiceClient;
import java.time.Duration;

/**
 * This CSR builder factory creates {@link CsrBuilder} instances with a common
 * KMS client and key cache. The default key cache time is 60 minutes.
 */
public class CsrBuilderFactory {

    /**
     * A builder for the factory. Created via
     * {@link CsrBuilderFactory#builder(KeyManagementServiceClient)}.
     */
    public static class Builder {

        private final KeyManagementServiceClient client;
        private Duration cacheDuration;

        private Builder(KeyManagementServiceClient client) {
            this.client = client;
        }

        /**
         * The key cache duration to use.
         * 
         * @param duration
         *            Duration to use, if null it will default to 60 minutes
         * @return This builder
         */
        public Builder withKeyCacheDuration(Duration duration) {
            this.cacheDuration = duration;
            return this;
        }

        /**
         * Create a new builder factory. If a duration is not set it will default to 60
         * minutes.
         * 
         * @return A new factory, never null
         */
        public CsrBuilderFactory build() {
            if (this.cacheDuration == null) {
                this.cacheDuration = Duration.ofMinutes(60);
            }
            KmsServiceClient kmsClient = new DefaultKmsServiceClient(client);
            KmsKeyCache cache = new KmsKeyCache(cacheDuration, kmsClient);
            return new CsrBuilderFactory(kmsClient, cache);
        }

    }

    /**
     * Create a new factory builder given a GCP KMS client.
     * 
     * @param client
     *            Client to use, must not be null
     * @return A new builder, never null
     */
    public static Builder builder(KeyManagementServiceClient client) {
        return new Builder(Preconditions.checkNotNull(client));
    }

    private final KmsServiceClient kmsClient;
    private final KmsKeyCache cache;

    private CsrBuilderFactory(KmsServiceClient kmsClient, KmsKeyCache cache) {
        this.kmsClient = kmsClient;
        this.cache = cache;
    }

    /**
     * Create a new CSR builder based on the factory configured KMS client and key
     * cache.
     * 
     * @return A new CSR builder, never null
     */
    public CsrBuilder builder() {
        return new CsrBuilder(kmsClient, cache);
    }
}
