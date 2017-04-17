/*
 * @(#) RSA256.java
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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Class to implement SHA-256 with RSA.
 */
public class RSA256 extends RSA {

    public static final String algorithmJOSECode = "RS256";
    public static final String algorithmJCAName = "SHA256withRSA";

    public RSA256(PublicKey publicKey, PrivateKey privateKey) {
        super(publicKey, privateKey);
    }

    public RSA256(PrivateKey privateKey) {
        super(null, privateKey);
    }

    public RSA256(PublicKey publicKey) {
        super(publicKey, null);
    }

    public RSA256(KeyPair keyPair) {
        super(keyPair.getPublic(), keyPair.getPrivate());
    }

    @Override
    public String getAlgorithmJOSECode() {
        return algorithmJOSECode;
    }

    @Override
    public String getAlgorithmJCAName() {
        return algorithmJCAName;
    }

}
