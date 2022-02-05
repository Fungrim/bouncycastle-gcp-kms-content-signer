package io.github.fungrim.bouncycastle.kms.signer;

import java.io.StringWriter;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.KeyManagementServiceClient;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import io.github.fungrim.bouncycastle.kms.client.DefaultKmsServiceClient;
import io.github.fungrim.bouncycastle.kms.client.KmsServiceClient;
import io.github.fungrim.bouncycastle.kms.util.Keys;

public class ManualKmsContentSignerTest {
    
    public static void main(String[] args) throws Exception {
        CryptoKeyVersionName keyName = CryptoKeyVersionName.parse(args[0]);
        try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
            KmsServiceClient kmsClient = new DefaultKmsServiceClient(client);
            CryptoKeyVersion key = kmsClient.getKey(keyName);
            ContentSigner kmsContentSigner = new KmsContentSigner(kmsClient, keyName, key.getAlgorithm());
            byte[] publicKeyPem = kmsClient.getPublicKeyPem(keyName);
            PublicKey pk = Keys.toPublicKey(key.getAlgorithm(), publicKeyPem);

            PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=io.github.fungrim, O=Fungrim Consulting AB, OU=, C=SE, L=Stockholm"), pk);
            PKCS10CertificationRequest csr = builder.build(kmsContentSigner);

            PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
            StringWriter csrString = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(csrString);
            pemWriter.writeObject(pemObject);
            pemWriter.close();
            csrString.close();

            //Certificate request will be printed into STDOUT
            System.out.println(csrString);
        
        }
    }
}
