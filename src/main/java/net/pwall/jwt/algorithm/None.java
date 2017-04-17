/*
 * @(#) None.java
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

import net.pwall.jwt.JWTException;
import net.pwall.jwt.SigningAlgorithm;
import net.pwall.jwt.VerifyingAlgorithm;

/**
 *
 */
public class None implements SigningAlgorithm, VerifyingAlgorithm {

    public static final String algorithmJOSECode = "none";
    public static final String algorithmJCAName = "none";

    @Override
    public String getAlgorithmJOSECode() {
        return algorithmJOSECode;
    }

    @Override
    public String getAlgorithmJCAName() {
        return algorithmJCAName;
    }

    @Override
    public void verify(byte[] data, byte[] code) {
        if (code.length > 0)
            throw new JWTException("Verification error");
    }

    @Override
    public byte[] sign(byte[] data) {
        return new byte[0];
    }

    public static None create() {
        return new None();
    }

}
