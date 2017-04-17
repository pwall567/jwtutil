/*
 * @(#) KeyUtil.java
 */

package net.pwall.jwt.util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import net.pwall.jwt.JWTException;

/**
 * Key utilities.
 */
public class KeyUtil {

    public static PublicKey createPublicKey(byte[] data, String algorithm) {
        EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(Objects.requireNonNull(data));
        try {
            return KeyFactory.getInstance(algorithm).generatePublic(encodedKeySpec);
        }
        catch (InvalidKeySpecException e) {
            throw new JWTException("Invalid key", e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new JWTException("No such algorithm", e);
        }
    }

    public static PrivateKey createPrivateKey(byte[] data, String algorithm) {
        EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(Objects.requireNonNull(data));
        try {
            return KeyFactory.getInstance(algorithm).generatePrivate(encodedKeySpec);
        }
        catch (InvalidKeySpecException e) {
            throw new JWTException("Invalid key", e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new JWTException("No such algorithm", e);
        }
    }

}
