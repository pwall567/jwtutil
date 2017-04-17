/*
 * @(#) Base64.java
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

package net.pwall.jwt.util;

import java.io.IOException;

/**
 * Encode and decode Base64.  This functionality exists in a variety of other libraries, but
 * those libraries generally include a lot of other unneeded code.
 *
 * @author  Peter Wall
 */
public class Base64 {

    private static final byte[] base64Bytes = new byte[64];
    private static final byte[] base64URLBytes = new byte[64];
    private static final byte[] reverseBytes = new byte[128];

    static {
        for (int i = 0; i < 128; i++)
            reverseBytes[i] = (byte)0xFF;

        for (int i = 0; i < 26; i++) {
            base64Bytes[i] = (byte)('A' + i);
            base64URLBytes[i] = (byte)('A' + i);
            reverseBytes['A' + i] = (byte)i;
        }

        for (int i = 0; i < 26; i++) {
            base64Bytes[i + 26] = (byte)('a' + i);
            base64URLBytes[i + 26] = (byte)('a' + i);
            reverseBytes['a' + i] = (byte)(i + 26);
        }

        for (int i = 0; i < 10; i++) {
            base64Bytes[i + 52] = (byte)('0' + i);
            base64URLBytes[i + 52] = (byte)('0' + i);
            reverseBytes['0' + i] = (byte)(i + 52);
        }

        base64Bytes[62] = (byte)'+';
        reverseBytes['+'] = (byte)62;
        base64URLBytes[62] = (byte)'-';
        reverseBytes['-'] = (byte)62;

        base64Bytes[63] = (byte)'/';
        reverseBytes['/'] = (byte)63;
        base64URLBytes[63] = (byte)'_';
        reverseBytes['_'] = (byte)63;
    }

    /**
     * Private constructor - do not instantiate.
     */
    private Base64() {
    }

    /**
     * Encode a byte array into Base64.
     *
     * @param   data    the source data
     * @return          the encoded data
     * @throws  NullPointerException if the data is null
     */
    public static byte[] encode(byte[] data) {
        int n = data.length;
        byte[] bytes = new byte[(n + 2) / 3 * 4];
        int x = 0;
        for (int i = 0; i < n; i += 3) {
            int a = data[i];
            bytes[x++] = base64Bytes[(a >> 2) & 0x3F];
            if (i + 1 == n) {
                bytes[x++] = base64Bytes[(a << 4) & 0x30];
                bytes[x++] = '=';
                bytes[x] = '=';
                break;
            }
            int b = data[i + 1];
            bytes[x++] = base64Bytes[((a << 4) & 0x30) | ((b >> 4) & 0x0F)];
            if (i + 2 == n) {
                bytes[x++] = base64Bytes[(b << 2) & 0x3C];
                bytes[x] = '=';
                break;
            }
            int c = data[i + 2];
            bytes[x++] = base64Bytes[((b << 2) & 0x3C) | ((c >> 6) & 0x03)];
            bytes[x++] = base64Bytes[c & 0x3F];
        }
        return bytes;
    }

    /**
     * Encode a byte array into the URL variant of Base64.  This variant uses different
     * characters for the last two positions in the encoding table, and it doesn't pad with
     * equal signs.
     *
     * @param   data    the source data
     * @return          the encoded data
     * @throws  NullPointerException if the data is null
     */
    public static byte[] encodeURL(byte[] data) {
        int n = data.length;
        byte[] bytes = new byte[(n * 4 + 2) / 3];
        int x = 0;
        for (int i = 0; i < n; i += 3) {
            int a = data[i];
            bytes[x++] = base64URLBytes[(a >> 2) & 0x3F];
            if (i + 1 == n) {
                bytes[x] = base64URLBytes[(a << 4) & 0x30];
                break;
            }
            int b = data[i + 1];
            bytes[x++] = base64URLBytes[((a << 4) & 0x30) | ((b >> 4) & 0x0F)];
            if (i + 2 == n) {
                bytes[x] = base64URLBytes[(b << 2) & 0x3C];
                break;
            }
            int c = data[i + 2];
            bytes[x++] = base64URLBytes[((b << 2) & 0x3C) | ((c >> 6) & 0x03)];
            bytes[x++] = base64URLBytes[c & 0x3F];
        }
        return bytes;
    }

    /**
     * Append a byte array to an {@link Appendable} as Base64-encoded characters.
     *
     * @param   app     the {@link Appendable}
     * @param   data    the source data
     * @throws IOException if thrown by the {@link Appendable}
     * @throws  NullPointerException if the data is null
     */
    public static void appendEncoded(Appendable app, byte[] data) throws IOException {
        appendEncoded(app, data, 0, data.length);
    }

    public static void appendEncoded(Appendable app, byte[] data, int start, int end)
            throws IOException {
        for (int i = start; i < end; i++) {
            int a = data[i];
            app.append((char)(base64Bytes[(a >> 2) & 0x3F]));
            if (i + 1 == end) {
                app.append((char)(base64Bytes[(a << 4) & 0x30])).append('=').append('=');
                break;
            }
            int b = data[i + 1];
            app.append((char)(base64Bytes[((a << 4) & 0x30) | ((b >> 4) & 0x0F)]));
            if (i + 2 == end) {
                app.append((char)(base64Bytes[(b << 2) & 0x3C])).append('=');
                break;
            }
            int c = data[i + 2];
            app.append((char)(base64Bytes[((b << 2) & 0x3C) | ((c >> 6) & 0x03)]));
            app.append((char)(base64Bytes[c & 0x3F]));
        }
    }

    /**
     * Decode a byte array from Base64.  Both the original and the URL variants are handled.
     *
     * @param   data    the source data
     * @return          the decoded data
     * @throws  IllegalArgumentException if the data is not valid Base64
     * @throws  NullPointerException if the data is null
     */
    public static byte[] decode(byte[] data) {
        int n = data.length;
        if ((n & 3) == 0) { // length divisible by 4 - could have trailing = sign(s)
            if (n > 0) {
                if (data[n - 1] == '='){
                    n--;
                    if (data[n - 1] == '=')
                        n--;
                }
            }
        }
        else { // otherwise length can't be 1, 5, 9, 13 ...
            if ((n & 3) == 1)
                throw new IllegalArgumentException("Incorrect number of bytes for Base64");
        }
        byte[] bytes = new byte[(n * 3) >> 2];
        int x = 0;
        for (int i = 0; i < n; i += 4) {
            int a = decodeByte(data[i]);
            int b = decodeByte(data[i + 1]);
            bytes[x++] = (byte)(((a << 2) & 0xFC) | ((b >> 4) & 0x03));
            if (i + 2 >= n) {
                if ((b & 0xF) != 0)
                    throw new IllegalArgumentException("Illegal character in Base64");
                break;
            }
            int c = decodeByte(data[i + 2]);
            bytes[x++] = (byte)(((b << 4) & 0xF0) | ((c >> 2) & 0xF));
            if (i + 3 >= n) {
                if ((c & 3) != 0)
                    throw new IllegalArgumentException("Illegal character in Base64");
                break;
            }
            int d = decodeByte(data[i + 3]);
            bytes[x++] = (byte)(((c << 6) & 0xC0) | d);
        }
        return bytes;
    }

    /**
     * Decode a {@link CharSequence} ({@link String}, {@link StringBuilder} etc.) from Base64.
     * Both the original and the URL variants are handled.
     *
     * @param   data    the source data
     * @return          the decoded data
     * @throws  IllegalArgumentException if the data is not valid Base64
     * @throws  NullPointerException if the data is null
     */
    public static byte[] decode(CharSequence data) {
        int n = data.length();
        if ((n & 3) == 0) { // length divisible by 4 - could have trailing = sign(s)
            if (n > 0) {
                if (data.charAt(n - 1) == '='){
                    n--;
                    if (data.charAt(n - 1) == '=')
                        n--;
                }
            }
        }
        else { // otherwise length can't be 1, 5, 9, 13 ...
            if ((n & 3) == 1)
                throw new IllegalArgumentException("Incorrect number of bytes for Base64");
        }
        byte[] bytes = new byte[(n * 3) >> 2];
        int x = 0;
        for (int i = 0; i < n; i += 4) {
            int a = decodeByte(data.charAt(i));
            int b = decodeByte(data.charAt(i + 1));
            bytes[x++] = (byte)(((a << 2) & 0xFC) | ((b >> 4) & 0x03));
            if (i + 2 >= n) {
                if ((b & 0xF) != 0)
                    throw new IllegalArgumentException("Illegal character in Base64");
                break;
            }
            int c = decodeByte(data.charAt(i + 2));
            bytes[x++] = (byte)(((b << 4) & 0xF0) | ((c >> 2) & 0xF));
            if (i + 3 >= n) {
                if ((c & 3) != 0)
                    throw new IllegalArgumentException("Illegal character in Base64");
                break;
            }
            int d = decodeByte(data.charAt(i + 3));
            bytes[x++] = (byte)(((c << 6) & 0xC0) | d);
        }
        return bytes;
    }

    private static int decodeByte(int b) {
        if ((b & ~0x7F) == 0) {
            byte result = reverseBytes[b];
            if ((result & ~0x3F) == 0)
                return result;
        }
        throw new IllegalArgumentException("Illegal character in Base64");
    }

}
