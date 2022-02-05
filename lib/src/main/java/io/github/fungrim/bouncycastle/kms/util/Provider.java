package io.github.fungrim.bouncycastle.kms.util;

@FunctionalInterface
public interface Provider<T> {
    
    public T get();

}
