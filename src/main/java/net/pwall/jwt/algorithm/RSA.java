/*
 * @(#) RSA.java
 *
 * jsonutil JWT Utility Library
 * Copyright (c) 2017 Peter Wall
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package net.pwall.jwt.algorithm;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import net.pwall.jwt.JWTException;
import net.pwall.jwt.SigningAlgorithm;
import net.pwall.jwt.VerifyingAlgorithm;

/**
 * Abstract class for RSA algorithms.
 */
public abstract class RSA implements SigningAlgorithm, VerifyingAlgorithm {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSA(PublicKey publicKey, PrivateKey privateKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    public byte[] sign(byte[] data) {
        if (privateKey == null)
            throw new JWTException("No private key");
        try {
            Signature s = Signature.getInstance(getAlgorithmJCAName());
            s.initSign(privateKey);
            s.update(data);
            return s.sign();
        }
        catch (NoSuchAlgorithmException e) {
            throw new JWTException("No such algorithm", e);
        }
        catch (InvalidKeyException e) {
            throw new JWTException("Invalid key", e);
        }
        catch (SignatureException e) {
            throw new JWTException("Error on signature", e);
        }
    }

    @Override
    public void verify(byte[] data, byte[] code) {
        if (publicKey == null)
            throw new JWTException("No public key");
        // to be completed
        try {
            Signature s = Signature.getInstance(getAlgorithmJCAName());
            s.initVerify(publicKey);
            s.update(data);
            if (!s.verify(code))
                throw new JWTException("Signature does not verify");
        }
        catch (NoSuchAlgorithmException e) {
            throw new JWTException("No such algorithm", e);
        }
        catch (InvalidKeyException e) {
            throw new JWTException("Invalid key", e);
        }
        catch (SignatureException e) {
            throw new JWTException("Error on signature", e);
        }
    }

}
