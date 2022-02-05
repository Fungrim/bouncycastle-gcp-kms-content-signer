# GCP KMS CSR Generation
A small utility library that creates CSR's where the private key is stored in GCP KMS. 

## TL;DR

```java
try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {

  // create builder factory that will cache key meta data
  CsrBuilderFactory factory = CsrBuilderFactory.builder(client)
    .withKeyCacheDuration(Duration.ofMinutes(20))
    .build();
    
  // you need a key for the csr
  String resourceId = "projects/your-project/locations/your-location/keyRings/your-keyring/cryptoKeys/your-key/cryptoKeyVersions/version"
  CryptoKeyVersionName keyName = CryptoKeyVersionName.parse(resourceId);
            
  // create a csr using a builder
  String csrPem = factory.builder()
    .forPrincipal(new X500Principal("CN=io.github.fungrim, O=Fungrim Consulting AB, OU=, C=SE, L=Stockholm"))
    .withKey(keyName)
    .build()
    .asPem();

  // profit!!
  System.out.println(csrPem);
          
}
```
