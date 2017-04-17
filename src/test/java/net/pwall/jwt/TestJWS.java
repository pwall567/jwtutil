/*
 * @(#) TestJWS.java
 */

package net.pwall.jwt;

import static org.junit.Assert.*;

import org.junit.Test;

import net.pwall.jwt.algorithm.HMAC;

/**
 * Test class for JWS.
 */
public class TestJWS {

    public static final String issuer = "http://pwall.net/JWT/test";
    public static final String claimName = "http://pwall.net/JWT/testClaimName";
    public static final String claimValue = "testClaimValue";

    @Test
    public void test() {
        byte[] key = "super-secret01234567890123456789".getBytes();
//        byte[] key = "secret".getBytes();
        JWS jws = new JWS();
        jws.setAlgorithm(HMAC.create(256, key));
        jws.setIssuer(issuer);
        jws.setClaim(claimName, claimValue);
        byte[] signed = jws.outputCompact();
        System.out.println("[" + signed.length + " bytes] " + new String(signed));

        JWS jws2 = JWS.decode(signed, HMAC.create(256, key));

        assertEquals(issuer, jws2.getIssuer());
        assertEquals(claimValue, jws2.getClaim(claimName));
    }

}
