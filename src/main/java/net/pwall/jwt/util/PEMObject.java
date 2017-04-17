/*
 * @(#) PEMObject.java
 */

package net.pwall.jwt.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * An object represented by a PEM file.
 */
public class PEMObject {

    public static final String BEGIN_PREFIX = "-----BEGIN ";
    public static final String END_PREFIX = "-----END ";

    private String type;
    private Map<String, String> headers;
    private byte[] data;

    /**
     * Construct a {@code PEMObject} with the given type, headers and data.
     *
     * @param   type    the type (e.g. "PUBLIC KEY")
     * @param   headers the headers
     * @param   data    the data
     */
    public PEMObject(String type, Map<String, String> headers, byte[] data) {
        this.type = type;
        this.headers = headers == null ? null : Collections.unmodifiableMap(headers);
        this.data = data;
    }

    /**
     * Construct a {@code PEMObject} with the given type and data.
     *
     * @param   type    the type (e.g. "PUBLIC KEY")
     * @param   data    the data
     */
    public PEMObject(String type, byte[] data) {
        this(type, null, data);
    }

    public String getType() {
        return type;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public byte[] getData() {
        return data;
    }

    public String getHeader(String key) {
        return headers == null ? null : headers.get(key);
    }

    public static PEMObject read(Reader rdr) throws IOException {
        BufferedReader brdr = rdr instanceof BufferedReader ? (BufferedReader)rdr :
                new BufferedReader(rdr);
        String line;
        for (;;) {
            line = brdr.readLine();
            if (line == null)
                return null;
            if (line.startsWith(BEGIN_PREFIX))
                break;
        }
        int i = BEGIN_PREFIX.length();
        int j = line.indexOf('-', i);
        if (j < 0)
            throw new IllegalArgumentException("PEM Start line not valid");
        String type = line.substring(i, j).trim();
        Map<String, String> headers = null;
        StringBuilder data = new StringBuilder();
        for (;;) {
            line = brdr.readLine();
            if (line == null)
                throw new IllegalArgumentException("PEM End line not found");
            if (line.startsWith(END_PREFIX))
                break;
            i = line.indexOf(':');
            if (i >= 0) {
                String key = line.substring(0, i).trim();
                String value = line.substring(i + 1).trim();
                if (headers == null)
                    headers = new HashMap<>();
                headers.put(key, value);
            }
            else
                data.append(line.trim());
        }
        return new PEMObject(type, headers, Base64.decode(data));
    }

}
