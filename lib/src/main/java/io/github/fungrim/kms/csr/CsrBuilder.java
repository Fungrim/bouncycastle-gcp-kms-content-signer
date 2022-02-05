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


import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.common.base.Preconditions;
import io.github.fungrim.kms.csr.client.KmsServiceClient;
import io.github.fungrim.kms.csr.signer.KmsContentSigner;
import java.io.IOException;
import java.io.StringWriter;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * This CSR builder operates on a key cache and a KMS client to generate CSR:s
 * given a specific crypto key version and an X500 principal. E.g.:
 * 
 * <pre>
 * CsrBuilderFactory factory = // create builder factory
 * String csrPem = factory.builder()
 *              .forPrincipal(new X500Principal("CN=io.github.fungrim, O=Fungrim Consulting AB, OU=, C=SE, L=Stockholm"))
 *              .withKey(keyName)
 *              .build()
 *              .asPem();
 * </pre>
 */
public class CsrBuilder {

    /**
     * The result of a built CSR. Currently it can only be retrieved as a PEM in
     * string format.
     */
    public static class Result {

        private final PKCS10CertificationRequest csr;

        private Result(PKCS10CertificationRequest csr) {
            this.csr = csr;
        }

        /**
         * @return The CSR as a PEM string
         * @throws IOException
         *             If failing to write the PEM
         */
        public String asPem() throws IOException {
            PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
            StringWriter csrString = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(csrString);
            pemWriter.writeObject(pemObject);
            pemWriter.close();
            csrString.close();
            return csrString.toString();
        }
    }

    private final KmsServiceClient client;
    private final KmsKeyCache cache;

    private CryptoKeyVersionName keyName;
    private X500Principal principal;

    /**
     * @param client
     *            KMS client, must not be null
     * @param cache
     *            Key cache, must not be null
     */
    CsrBuilder(KmsServiceClient client, KmsKeyCache cache) {
        this.client = Preconditions.checkNotNull(client);
        this.cache = Preconditions.checkNotNull(cache);
    }

    /**
     * Set the crypto key version to use.
     * 
     * @param keyName
     *            The key to use, must not be nnull
     * @return This builder, never null
     */
    public CsrBuilder withKey(CryptoKeyVersionName keyName) {
        this.keyName = Preconditions.checkNotNull(keyName);
        return this;
    }

    /**
     * Set the principal for the request.
     * 
     * @param principal
     *            The principal to use, must not be null
     * @return This builder, never null
     */
    public CsrBuilder forPrincipal(X500Principal principal) {
        this.principal = Preconditions.checkNotNull(principal);
        return this;
    }

    /**
     * Build the CSR, will thro errors if the crypto key version or principal are
     * not set, and if the key can't be accessed.
     * 
     * @return The CSR result, never null
     */
    public Result build() {
        Preconditions.checkNotNull(this.keyName, "Missing crypto key version name");
        Preconditions.checkNotNull(this.principal, "Missing X500 principal");
        KmsKeyCache.Entry entry = cache.get(this.keyName);
        return new Result(new JcaPKCS10CertificationRequestBuilder(this.principal, entry.getPublicKey())
                .build(new KmsContentSigner(client, keyName, entry.getAlgorithm())));
    }
}
