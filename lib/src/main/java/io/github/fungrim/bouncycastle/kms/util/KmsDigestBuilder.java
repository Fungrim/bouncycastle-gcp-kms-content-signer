package io.github.fungrim.bouncycastle.kms.util;

import com.google.cloud.kms.v1.Digest;

@FunctionalInterface
public interface KmsDigestBuilder {
    
    public Digest build(byte[] digestBytes);
    
}
