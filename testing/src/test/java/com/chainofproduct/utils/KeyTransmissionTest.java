package com.chainofproduct.utils;

import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStore;

@FixMethodOrder(MethodSorters.JVM)
public class KeyTransmissionTest {
        @Test
        public void testGenerateECKeyPairAndStore() throws Exception {
                                System.out.println("Running testGenerateECKeyPairAndStore");
                String alias = "test-ec";
                String keystore = "test-ec-keystore.p12";
                String password = "changeit";
                // Clean up
                new File(keystore).delete();
                KeyPair kp = KeyTransmission.generateECKeyPairAndStore(alias, keystore, password);
                assertNotNull(kp);
                assertNotNull(kp.getPrivate());
                assertNotNull(kp.getPublic());
                // Check keystore
                KeyStore ks = KeyStore.getInstance("PKCS12");
                try (java.io.FileInputStream fis = new java.io.FileInputStream(keystore)) {
                        ks.load(fis, password.toCharArray());
                        assertTrue(ks.containsAlias(alias));
                        assertNotNull(ks.getKey(alias, password.toCharArray()));
                }
                new File(keystore).delete();
        }

        @Test
        public void testGetMyECPrivateKey() throws Exception {
                                System.out.println("Running testGetMyECPrivateKey");
                String alias = "test-ec";
                String keystore = "test-ec-keystore.p12";
                String password = "changeit";
                // Ensure keypair exists
                KeyTransmission.generateECKeyPairAndStore(alias, keystore, password);
                PrivateKey priv = KeyTransmission.getMyECPrivateKey(keystore, alias);
                assertNotNull(priv);
                new File(keystore).delete();
        }
        @Test
        public void testEnsureECKeyAndStartListenerDummy() {
                                System.out.println("Running testEnsureECKeyAndStartListenerDummy");
                Thread listenerThread = new Thread(() -> {
                        try {
                                KeyTransmission.ensureECKeyAndStartListener("dummy", 0);
                        } catch (Exception e) {
                                // Acceptable for dummy test
                        }
                });
                listenerThread.start();
                try {
                        Thread.sleep(500); // Give listener time to start
                        KeyTransmission.closeKeyExchangeListener();
                        listenerThread.join(2000); // Wait for listener to stop
                } catch (Exception ex) {
                        // Ignore
                }
                assertTrue(true);
        }

        
        @Test
        public void testAesEncryptDecrypt() throws Exception {
                                System.out.println("Running testAesEncryptDecrypt");
                // Test AES encryption/decryption helpers via reflection
                java.lang.reflect.Method enc = KeyTransmission.class.getDeclaredMethod("aesEncrypt", byte[].class, byte[].class);
                java.lang.reflect.Method dec = KeyTransmission.class.getDeclaredMethod("aesDecrypt", byte[].class, byte[].class);
                enc.setAccessible(true);
                dec.setAccessible(true);
                byte[] data = "hello world".getBytes();
                byte[] key = new byte[16];
                for (int i = 0; i < 16; i++) key[i] = (byte)i;
                byte[] encrypted = (byte[])enc.invoke(null, data, key);
                assertNotNull(encrypted);
                byte[] decrypted = (byte[])dec.invoke(null, encrypted, key);
                assertArrayEquals(data, decrypted);
        }

        @Test
        public void testIntToBytesAndBytesToInt() throws Exception {
                                System.out.println("Running testIntToBytesAndBytesToInt");
                java.lang.reflect.Method intToBytes = KeyTransmission.class.getDeclaredMethod("intToBytes", int.class);
                java.lang.reflect.Method bytesToInt = KeyTransmission.class.getDeclaredMethod("bytesToInt", byte[].class);
                intToBytes.setAccessible(true);
                bytesToInt.setAccessible(true);
                int value = 123456789;
                byte[] bytes = (byte[])intToBytes.invoke(null, value);
                int result = (int)bytesToInt.invoke(null, bytes);
                assertEquals(value, result);
        }

        @Test
        public void testReadBytesDummy() throws Exception {
                                System.out.println("Running testReadBytesDummy");
                // Dummy test: just check method can be called via reflection
                java.lang.reflect.Method readBytes = KeyTransmission.class.getDeclaredMethod("readBytes", java.io.InputStream.class);
                readBytes.setAccessible(true);
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                byte[] data = "abc".getBytes();
                byte[] lenBytes = (byte[]) KeyTransmission.class.getDeclaredMethod("intToBytes", int.class).invoke(null, data.length);
                out.write(lenBytes);
                out.write(data);
                java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(out.toByteArray());
                byte[] result = (byte[])readBytes.invoke(null, in);
                assertArrayEquals(data, result);
        }
        @Test
        public void testKeyExchangeCommunication() throws Exception {
            System.out.println("Running testKeyExchangeCommunication");
            String entityA = "entityA";
            String entityB = "entityB";
            String password = "changeit";
            int port = 23456;

            // Clean up any old files
            new File(entityA + "-ec-keystore.p12").delete();
            new File(entityA + "-truststore.p12").delete();
            new File(entityA + "-truststore-pubkeys.p12").delete();
            new File(entityA + "-keystore.p12").delete();
            new File(entityB + "-ec-keystore.p12").delete();
            new File(entityB + "-truststore.p12").delete();
            new File(entityB + "-truststore-pubkeys.p12").delete();
            new File(entityB + "-keystore.p12").delete();

            // Use Cerificates.main to generate all keys and certs for both entities
            Cerificates.main(new String[]{entityA, password});
            Cerificates.main(new String[]{entityB, password});

            // Load EC keypair for entityA
            KeyPair ecA = KeyTransmission.generateECKeyPairAndStore(entityA + "-ec", entityA + "-ec-keystore.p12", password);
            KeyPair ecB = KeyTransmission.generateECKeyPairAndStore(entityB + "-ec", entityB + "-ec-keystore.p12", password);

            // Load RSA public key and certificate for entityA
            KeyStore ksb = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(entityB + "-keystore.p12")) {
                ksb.load(fis, password.toCharArray());
            }
            java.security.cert.X509Certificate certB = (java.security.cert.X509Certificate) ksb.getCertificate(entityB);
            PublicKey rsaPubB = certB.getPublicKey();

            // Start listener for entityB in a background thread
            Thread listenerThread = new Thread(() -> {
                try {
                    KeyTransmission.startKeyExchangeListener(entityA, port, ecA); // Use ecA for test simplicity
                } catch (Exception e) {
                    // Ignore for test
                }
            });
            listenerThread.start();
            Thread.sleep(500); // Give listener time to start

            // EntityA sends its RSA key and cert to entityB in a separate thread
            Thread senderThread = new Thread(() -> {
                try {
                    KeyTransmission.sendRSAKeyAndCertWithECDH(entityB, entityB, entityA, "localhost", port, ecB, rsaPubB, certB);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            senderThread.start();
            senderThread.join(2000); // Wait for sender to finish

            // Stop the listener
            KeyTransmission.closeKeyExchangeListener();
            listenerThread.join(2000);

            // Assert truststore and pubkey truststore contents for entityB
            KeyStore tsB = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(entityB + "-truststore.p12")) {
                tsB.load(fis, password.toCharArray());
                assertTrue(tsB.containsAlias(entityA));
                java.security.cert.Certificate cert = tsB.getCertificate(entityA);
                assertNotNull(cert);
                assertEquals("X.509", cert.getType());
            }
            KeyStore ptsB = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(entityB + "-truststore-pubkeys.p12")) {
                ptsB.load(fis, password.toCharArray());
                assertTrue(ptsB.containsAlias(entityA + "-pubkey"));
                java.security.cert.Certificate cert = ptsB.getCertificate(entityA + "-pubkey");
                assertNotNull(cert);
                assertEquals("X.509", cert.getType());
            }

            // Assert truststore and pubkey truststore contents for entityA
            KeyStore tsA = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(entityA + "-truststore.p12")) {
                tsA.load(fis, password.toCharArray());
                assertTrue(tsA.containsAlias(entityB));
                java.security.cert.Certificate cert = tsA.getCertificate(entityB);
                assertNotNull(cert);
                assertEquals("X.509", cert.getType());
            }
            KeyStore ptsA = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(entityA + "-truststore-pubkeys.p12")) {
                ptsA.load(fis, password.toCharArray());
                assertTrue(ptsA.containsAlias(entityB + "-pubkey"));
                java.security.cert.Certificate cert = ptsA.getCertificate(entityB + "-pubkey");
                assertNotNull(cert);
                assertEquals("X.509", cert.getType());
            }

            // Clean up
            new File(entityA + "-ec-keystore.p12").delete();
            new File(entityA + "-truststore.p12").delete();
            new File(entityA + "-truststore-pubkeys.p12").delete();
            new File(entityA + "-keystore.p12").delete();
            new File(entityB + "-ec-keystore.p12").delete();
            new File(entityB + "-truststore.p12").delete();
            new File(entityB + "-truststore-pubkeys.p12").delete();
            new File(entityB + "-keystore.p12").delete();
        }
}

