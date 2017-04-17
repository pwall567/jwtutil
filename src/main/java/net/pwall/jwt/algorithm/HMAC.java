/*
 * @(#) HMAC.java
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
import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import net.pwall.jwt.JWTException;
import net.pwall.jwt.SigningAlgorithm;
import net.pwall.jwt.VerifyingAlgorithm;

/**
 * Abstract class for HMAC algorithms.
 */
public abstract class HMAC implements SigningAlgorithm, VerifyingAlgorithm {

    private Mac mac;

    public HMAC(byte[] secret) {
        String algorithmJCAName = getAlgorithmJCAName();
        try {
            mac = Mac.getInstance(algorithmJCAName);
            mac.init(new SecretKeySpec(Objects.requireNonNull(secret), getAlgorithmJCAName()));
        }
        catch (NoSuchAlgorithmException e) {
            throw new JWTException("Algorithm not found - " + algorithmJCAName);
        }
        catch (InvalidKeyException e) {
            throw new JWTException("Invalid key (" + algorithmJCAName + ')');
        }
    }

    @Override
    public byte[] sign(byte[] data) {
        return mac.doFinal(data);
    }

    @Override
    public void verify(byte[] data, byte[] code) {
        checkCodes(code, mac.doFinal(data));
    }

    protected static void checkCodes(byte[] expected, byte[] actual) {
        int len = actual.length;
        if (len != expected.length)
            throw new JWTException();
        for (int i = 0; i < len; i++)
            if (actual[i] != expected[i])
                throw new JWTException("Signature does not verify");
    }

    public static HMAC create(int width, byte[] secret) {
        switch (width) {

        case 256:
            return new HMAC256(secret);

        case 384:
            return new HMAC384(secret);

        case 512:
            return new HMAC512(secret);

        default:
            throw new JWTException("Invalid width - " + width);
        }
    }

    public static HMAC create(String width, byte[] secret) {
        switch (width) {

        case "256":
            return new HMAC256(secret);

        case "384":
            return new HMAC384(secret);

        case "512":
            return new HMAC512(secret);

        default:
            throw new JWTException("Invalid width - " + width);

        }
    }

}
