/*
 * @(#) JWT.java
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import net.pwall.json.JSONArray;
import net.pwall.json.JSONObject;

/**
 * Base class for JWT - JWS and JWE.
 *
 * @author  Peter Wall
 */
public abstract class JWT {

    public static final String ALGORITHM_HEADER_NAME = "alg";
    public static final String CONTENT_TYPE_HEADER_NAME = "cty";
    public static final String TYPE_HEADER_NAME = "typ";

    public static final String AUDIENCE_CLAIM_NAME = "aud";
    public static final String EXPIRATION_TIME_CLAIM_NAME = "exp";
    public static final String ISSUER_CLAIM_NAME = "iss";
    public static final String NOT_BEFORE_CLAIM_NAME = "nbf";
    public static final String SUBJECT_CLAIM_NAME = "sub";

    public static final String JWT_TYPE = "JWT";

    // NOTE - these arrays are searched by binary search and must be kept in ascending order
    public static String[] HEADER_NAMES = { ALGORITHM_HEADER_NAME, CONTENT_TYPE_HEADER_NAME,
            TYPE_HEADER_NAME };
    public static String[] CLAIM_NAMES = { AUDIENCE_CLAIM_NAME, EXPIRATION_TIME_CLAIM_NAME,
            ISSUER_CLAIM_NAME, NOT_BEFORE_CLAIM_NAME, SUBJECT_CLAIM_NAME };
    public static String[] ALGORITHM_NAMES = { "HS256" };

    private Algorithm algorithm;
    private JSONObject header;
    private JSONObject claims;

    public JWT() {
        algorithm = null;
        header = new JSONObject();
        header.putValue(TYPE_HEADER_NAME, JWT_TYPE);
        claims = new JSONObject();
    }

    public JWT(Algorithm algorithm) {
        this();
        setAlgorithm(algorithm);
    }

    // HEADER METHODS

    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
        if (algorithm != null)
            header.putValue(ALGORITHM_HEADER_NAME, algorithm.getAlgorithmJOSECode());
        else
            header.remove(ALGORITHM_HEADER_NAME);
    }

    public void setAlgorithm(String value) {
        if (value != null) {
            if (Arrays.binarySearch(ALGORITHM_NAMES, value) < 0)
                throw new JWTException("Illegal algorithm name: " + value);
            header.putValue(ALGORITHM_HEADER_NAME, value);
        }
        else
            header.remove(ALGORITHM_HEADER_NAME);
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public void setType(String value) {
        if (value != null) {
            if (!JWT_TYPE.equals(value))
                throw new JWTException("Type must be " + JWT_TYPE);
            header.putValue(TYPE_HEADER_NAME, value);
        }
        else
            header.remove(TYPE_HEADER_NAME);
    }

    public String getType() {
        return header.getString(TYPE_HEADER_NAME);
    }

    public void setContentType(String value) {
        if (value != null)
            header.putValue(CONTENT_TYPE_HEADER_NAME, value);
        else
            header.remove(CONTENT_TYPE_HEADER_NAME);
    }

    public String getContentType() {
        return header.getString(CONTENT_TYPE_HEADER_NAME);
    }

    public void setHeader(String name, String value) {
        if (Arrays.binarySearch(HEADER_NAMES, Objects.requireNonNull(name)) >= 0)
            throw new JWTException("Illegal header name: " + name);
        if (value != null)
            header.putValue(name, value);
        else
            header.remove(name);
    }

    public String getHeader(String name) {
        return header.getString(name);
    }

    protected void setHeader(JSONObject header) {
        this.header = header;
    }

    // CLAIMS METHODS

    public void setIssuer(String value) {
        if (value != null)
            claims.putValue(ISSUER_CLAIM_NAME, value);
        else
            claims.remove(ISSUER_CLAIM_NAME);
    }

    public String getIssuer() {
        return claims.getString(ISSUER_CLAIM_NAME);
    }

    public void setSubject(String value) {
        if (value != null)
            claims.putValue(SUBJECT_CLAIM_NAME, value);
        else
            claims.remove(SUBJECT_CLAIM_NAME);
    }

    public String getSubject() {
        return claims.getString(SUBJECT_CLAIM_NAME);
    }

    public void addAudience(String value) {
        Objects.requireNonNull(value);
        JSONArray audienceArray = claims.getArray(AUDIENCE_CLAIM_NAME);
        if (audienceArray != null) {
            for (int i = 0, n = audienceArray.size(); i < n; i++)
                if (audienceArray.get(i).toString().equals(value))
                    throw new JWTException("Duplicate audience value: " + value);
        }
        else {
            audienceArray = new JSONArray();
            claims.put(AUDIENCE_CLAIM_NAME, audienceArray);
        }
        audienceArray.addValue(value);
    }

    public void removeAudience(String value) {
        Objects.requireNonNull(value);
        JSONArray audienceArray = claims.getArray(AUDIENCE_CLAIM_NAME);
        if (audienceArray != null) {
            for (int i = 0, n = audienceArray.size(); i < n; i++) {
                if (audienceArray.get(i).toString().equals(value)) {
                    audienceArray.remove(i);
                    break;
                }
            }
            if (audienceArray.isEmpty())
                claims.remove(AUDIENCE_CLAIM_NAME);
        }
    }

    public String[] getAudienceArray() {
        List<String> list = new ArrayList<>();
        JSONArray audienceArray = claims.getArray(AUDIENCE_CLAIM_NAME);
        if (audienceArray != null)
            for (int i = 0, n = audienceArray.size(); i < n; i++)
                list.add(audienceArray.get(i).toString());
        return list.toArray(new String[list.size()]);
    }

    public void setExpirationTime(long value) {
        claims.putValue(EXPIRATION_TIME_CLAIM_NAME, value);
    }

    public void unsetExpirationTime() {
        claims.remove(EXPIRATION_TIME_CLAIM_NAME);
    }

    public void setNotBefore(long value) {
        claims.putValue(NOT_BEFORE_CLAIM_NAME, value);
    }

    public void unsetNotBefore() {
        claims.remove(NOT_BEFORE_CLAIM_NAME);
    }

    public void setClaim(String name, String value) {
        if (Arrays.binarySearch(CLAIM_NAMES, Objects.requireNonNull(name)) >= 0)
            throw new JWTException("Illegal claim name: " + name);
        if (value != null)
            claims.putValue(name, value);
        else
            claims.remove(name);
    }

    public String getClaim(String name) {
        return claims.getString(name);
    }

    protected void setClaims(JSONObject claims) {
        this.claims = claims;
    }

    protected String getHeaderJSON() {
        return header.toJSON();
    }

    protected String getClaimsJSON() {
        return claims.toJSON();
    }

    public abstract byte[] outputCompact();

    public static JWT decodeCompact(byte[] data, Algorithm ... algorithms) {
        int count = 0;
        for (int i = 0, n = data.length; i < n; i++)
            if (data[i] == '.')
                count++;
        if (count == 2)
            return JWS.decodeCompact(data, algorithms);
        if (count == 4)
            return JWE.decodeCompact(data, algorithms);
        throw new JWTException("JWT decode - incorrect format");
    }

    protected static byte[] getBytes(byte[] data, int start, int end) {
        int len = end - start;
        byte[] ba = new byte[len];
        System.arraycopy(data, start, ba, 0, len);
        return ba;
    }

    protected static int[] splitData(int number, byte[] data) {
        int count = 0;
        int[] dots = new int[number];
        for (int i = 0, n = data.length; i < n; i++) {
            if (data[i] == '.') {
                if (count == number)
                    throw new JWTException("Malformed JWT");
                dots[count] = i;
                count++;
            }
        }
        if (count < number)
            throw new JWTException("Malformed JWT");
        return dots;
    }

    protected static Algorithm findAlgorithm(String code, Algorithm[] algorithms) {
        for (int i = 0, n = algorithms.length; i < n; i++) {
            Algorithm algorithm = algorithms[i];
            if (algorithm.getAlgorithmJOSECode().equals(code))
                return algorithm;
        }
        throw new JWTException("Algorithm not accepted: " + code);
    }

    @SuppressWarnings("unused")
    public static JWT decodeJSON(byte[] data, Algorithm ... algorithms) {
        throw new JWTException("JWT decode - can't handle JSON format");
    }

    public static JWT decode(byte[] data, Algorithm ... algorithms) {
        if (data == null || data.length == 0)
            throw new JWTException("JWT decode empty or missing string");
        return data[0] == '{' ? decodeJSON(data, algorithms) : decodeCompact(data, algorithms);
    }

    public static JWT decode(String str, Algorithm ... algorithms) {
        return decode(str.getBytes(StandardCharsets.UTF_8), algorithms);
    }

}
