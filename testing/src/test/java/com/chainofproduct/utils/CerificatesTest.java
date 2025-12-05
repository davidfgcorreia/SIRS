package com.chainofproduct.utils;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.PublicKey;

public class CerificatesTest {
    @Test
    public void testGenerateAndCheckKeystores() throws Exception {
        String entity = "testentity";
        // Clean up any old files
        new File(entity + "-keystore.p12").delete();
        new File(entity + "-truststore.p12").delete();
        new File(entity + "-truststore-pubkeys.p12").delete();
        new File(entity + "-ec-keystore.p12").delete();

        // Generate keys and certs
        Cerificates.main(new String[]{entity});

        // Check keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(entity + "-keystore.p12")) {
            ks.load(fis, "changeit".toCharArray());
            assertTrue(ks.containsAlias(entity));
            assertNotNull(ks.getKey(entity, "changeit".toCharArray()));
            assertNotNull(ks.getCertificate(entity));
        }

        // Check truststore
        KeyStore ts = KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(entity + "-truststore.p12")) {
            ts.load(fis, "changeit".toCharArray());
            assertTrue(ts.containsAlias(entity));
            assertNotNull(ts.getCertificate(entity));
        }

        // Check pubkey truststore
        KeyStore pts = KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(entity + "-truststore-pubkeys.p12")) {
            pts.load(fis, "changeit".toCharArray());
            assertTrue(pts.containsAlias(entity + "-pubkey"));
            assertNotNull(pts.getCertificate(entity + "-pubkey"));
        }

        // Check EC keystore
        KeyStore ecKs = KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(entity + "-ec-keystore.p12")) {
            ecKs.load(fis, "changeit".toCharArray());
            assertTrue(ecKs.containsAlias(entity + "-ec"));
            assertNotNull(ecKs.getKey(entity + "-ec", "changeit".toCharArray()));
        }

        // Remove generated files after test
        new File(entity + "-keystore.p12").delete();
        new File(entity + "-truststore.p12").delete();
        new File(entity + "-truststore-pubkeys.p12").delete();
        new File(entity + "-ec-keystore.p12").delete();
    }
}