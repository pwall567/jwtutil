/*
 * @(#) JWS.java
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

package net.pwall.jwt;

import java.nio.charset.StandardCharsets;

import net.pwall.json.JSON;
import net.pwall.json.JSONObject;
import net.pwall.jwt.util.Base64;
import net.pwall.util.ByteArrayBuilder;
import net.pwall.util.Strings;

/**
 * JWS class.
 *
 * @author  Peter Wall
 */
public class JWS extends JWT {

    @Override
    public byte[] outputCompact() {

        Algorithm algorithm = getAlgorithm();
        if (algorithm == null)
            throw new JWTException("No algorithm provided");
        if (!(algorithm instanceof SigningAlgorithm))
            throw new JWTException("Algorithm invalid: " + algorithm.getAlgorithmJCAName());
        SigningAlgorithm sa = (SigningAlgorithm)algorithm;

        byte[] header = Strings.toUTF8(getHeaderJSON());
        byte[] claims = Strings.toUTF8(getClaimsJSON());

        ByteArrayBuilder bab = new ByteArrayBuilder();
        bab.append(Base64.encodeURL(header));
        bab.append('.');
        bab.append(Base64.encodeURL(claims));

        byte[] signature = sa.sign(bab.toByteArray());
        bab.append('.');
        bab.append(Base64.encodeURL(signature));

        return bab.toByteArray();
    }

    public static JWS decodeCompact(byte[] data, Algorithm ... algorithms) {
        int[] dots = splitData(2, data);
        try {
            byte[] headerData = Base64.decode(getBytes(data, 0, dots[0]));
            JSONObject header = (JSONObject)JSON.parse(new String(headerData));
            String algorithmCode = header.getString(ALGORITHM_HEADER_NAME);
            Algorithm algorithm = findAlgorithm(algorithmCode, algorithms);
            if (!(algorithm instanceof VerifyingAlgorithm))
                throw new JWTException("Algorithm invalid: " + algorithm.getAlgorithmJCAName());
            VerifyingAlgorithm verifyingAlgorithm = (VerifyingAlgorithm)algorithm;
            verifyingAlgorithm.verify(getBytes(data, 0, dots[1]),
                    Base64.decode(getBytes(data, dots[1] + 1, data.length)));

            JWS jws = new JWS();
            jws.setHeader(header);
            byte[] claimsData = Base64.decode(getBytes(data, dots[0] + 1, dots[1]));
            jws.setClaims((JSONObject)JSON.parse(new String(claimsData)));

            return jws;
        }
        catch (Exception e) {
            throw new JWTException("Unexpected exception decoding JWT", e);
        }
    }

    public static JWS decodeCompact(String str, Algorithm ... algorithms) {
        return decodeCompact(str.getBytes(StandardCharsets.UTF_8), algorithms);
    }

    public static JWS decodeJSON(byte[] data, Algorithm ... algorithms) {
        throw new JWTException("JWT decode - can't handle JSON format");
    }

    public static JWS decode(byte[] data, Algorithm ... algorithms) {
        if (data == null || data.length == 0)
            throw new JWTException("JWT decode empty or missing string");
        return data[0] == '{' ? decodeJSON(data, algorithms) : decodeCompact(data, algorithms);
    }

    public static JWS decode(String str, Algorithm ... algorithms) {
        return decode(str.getBytes(StandardCharsets.UTF_8), algorithms);
    }

}
