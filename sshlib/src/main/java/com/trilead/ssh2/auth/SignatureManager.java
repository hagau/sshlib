package com.trilead.ssh2.auth;

import java.io.IOException;
import java.security.PublicKey;
import java.security.SecureRandom;

import jdk.nashorn.internal.objects.annotations.Getter;

public abstract class SignatureManager {

    public static final String SIGNATURE_ALGORITHM_RSA_SHA1 = "SHA1withRSA";
    public static final String SIGNATURE_ALGORITHM_DSA_SHA1 = "SHA1withDSA";
    public static final String SIGNATURE_ALGORITHM_EdDSA_SHA512 = "SHA-512";

    /**
     * Holds the public key which belongs to the private key which is used in the signing process.
     */
    private PublicKey mPublicKey;

    /**
     * Instantiates a new SignatureManager which needs a public key for the
     * later authentication process.
     * @param publicKey The public key.
     * @exception IllegalArgumentException Might be thrown id the public key is invalid.
     */
    public SignatureManager(PublicKey publicKey) throws IllegalArgumentException
    {
        if(publicKey == null)
        {
            throw new IllegalArgumentException("Public key must not be null");
        }
        mPublicKey = publicKey;
    }

    /**
     * This method should sign a given byte array message using the private key.
     * @param message The message which should be signed.
     * @param algorithm The signing algorithm which should be used.
     * @return The signed message.
     * @throws IOException This exception might be thrown during the signing process.
     */
    public abstract byte[] sign(byte[] message, String algorithm) throws IOException;

    @Getter
    public PublicKey getPublicKey()
    {
        return mPublicKey;
    }
}
