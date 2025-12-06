package com.chainofproduct.utils;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.PublicKey;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;

public class ApiCallsTest {
        private static final String password = "changeit";
        private static final String entityA = "client1";
        private static final String entityB = "server";
        private static final String entityTypeA = "client";
        private static final int clientNumA = 1;
        private static final String entityTypeB = "server";

        @org.junit.BeforeClass
        public static void setupCertificatesAndTruststores() throws Exception {
            System.out.println("[TEST] Cleaning up old keystore/truststore files...");
            System.out.println("[TEST] Generating keys and certs for entities: " + entityA + ", " + entityB);
            System.out.println("[TEST] Storing each other's certs and pubkeys in truststores...");
            // Clean up any old files before setup
            for (String entity : new String[]{entityA, entityB}) {
                new File(entity + "-keystore.p12").delete();
                new File(entity + "-truststore.p12").delete();
                new File(entity + "-truststore-pubkeys.p12").delete();
                new File(entity + "-ec-keystore.p12").delete();
            }
            // Generate keys and certs for both entities
            com.chainofproduct.utils.Cerificates.main(new String[]{entityA});
            com.chainofproduct.utils.Cerificates.main(new String[]{entityB});

            // Load keypairs and certs
            KeyStore ksA = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(entityA + "-keystore.p12")) {
                ksA.load(fis, password.toCharArray());
            }
            X509Certificate certA = (X509Certificate) ksA.getCertificate(entityA);
            PublicKey pubA = certA.getPublicKey();

            KeyStore ksB = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(entityB + "-keystore.p12")) {
                ksB.load(fis, password.toCharArray());
            }
            X509Certificate certB = (X509Certificate) ksB.getCertificate(entityB);
            PublicKey pubB = certB.getPublicKey();

            // Store each other's certs and pubkeys in truststores
            com.chainofproduct.utils.Cerificates.storeTruststore(entityA + "-truststore.p12", password, new String[]{entityB}, new X509Certificate[]{certB});
            com.chainofproduct.utils.Cerificates.storeTruststore(entityB + "-truststore.p12", password, new String[]{entityA}, new X509Certificate[]{certA});
            // For pubkey truststores, use the correct aliasing: <entity> (so entry is <entity>-pubkey)
            com.chainofproduct.utils.Cerificates.storePubKeyTruststore(entityA + "-truststore-pubkeys.p12", password, new String[]{entityB}, new PublicKey[]{pubB});
            com.chainofproduct.utils.Cerificates.storePubKeyTruststore(entityB + "-truststore-pubkeys.p12", password, new String[]{entityA}, new PublicKey[]{pubA});
        }

        @org.junit.AfterClass
        public static void cleanupCertificatesAndTruststores() {
                            System.out.println("[TEST] Cleaning up keystore/truststore files after tests...");
                for (String entity : new String[]{entityA, entityB}) {
                        new File(entity + "-keystore.p12").delete();
                        new File(entity + "-truststore.p12").delete();
                        new File(entity + "-truststore-pubkeys.p12").delete();
                        new File(entity + "-ec-keystore.p12").delete();
                }
        }
        @Test
        public void testActAsSenderAndHandleClientValid() throws Exception {
            System.out.println("[TEST] testActAsSenderAndHandleClientValid: Setting up SSLServerSocket with server's keystore and truststore...");
            java.security.KeyStore serverKeyStore = com.chainofproduct.utils.Cerificates.getKeystore(entityB, password);
            java.security.KeyStore serverTrustStore = com.chainofproduct.utils.Cerificates.getTruststore(entityB, password);
            System.out.println("[TEST] testActAsSenderAndHandleClientValid: Initializing KeyManagerFactory and TrustManagerFactory...");
            javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509");
            kmf.init(serverKeyStore, password.toCharArray());
            javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance("SunX509");
            tmf.init(serverTrustStore);
            System.out.println("[TEST] testActAsSenderAndHandleClientValid: Initializing SSLContext...");
            javax.net.ssl.SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());
            javax.net.ssl.SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
            javax.net.ssl.SSLServerSocket serverSocket = (javax.net.ssl.SSLServerSocket) ssf.createServerSocket(0);
            int port = serverSocket.getLocalPort();
            System.out.println("[TEST] testActAsSenderAndHandleClientValid: Server listening on port " + port);
            AtomicReference<byte[]> received = new AtomicReference<>();
            Thread serverThread = new Thread(() -> {
                System.out.println("[TEST] testActAsSenderAndHandleClientValid: Server thread started, waiting for client...");
                try (Socket client = serverSocket.accept()) {
                    System.out.println("[TEST] testActAsSenderAndHandleClientValid: Client connected, handling request...");
                    ApiCalls.handleClient(client, request -> {
                        System.out.println("[TEST] testActAsSenderAndHandleClientValid: Server received payload: " + (request == null ? "null" : new String(request)));
                        received.set(request);
                        return "RESPONSE".getBytes();
                    });
                } catch (Exception e) {
                    System.out.println("[TEST] testActAsSenderAndHandleClientValid: Exception in server thread: " + e.getMessage());
                }
                System.out.println("[TEST] testActAsSenderAndHandleClientValid: Server thread finished.");
            });
            serverThread.start();
            Thread.sleep(100); // Give server time to start
            System.out.println("[TEST] testActAsSenderAndHandleClientValid: Sending data from " + entityA + " to " + entityB + ": TESTDATA");
            byte[] result = ApiCalls.actAsSender("localhost", port, entityTypeA, clientNumA, entityB, "TESTDATA".getBytes());
            System.out.println("[TEST] testActAsSenderAndHandleClientValid: Received response: " + (result == null ? "null" : new String(result)));
            System.out.println("[TEST] testActAsSenderAndHandleClientValid: Asserting response and payload...");
            assertNotNull(result);
            assertEquals("RESPONSE", new String(result));
            assertEquals("TESTDATA", new String(received.get()));
            System.out.println("[TEST] testActAsSenderAndHandleClientValid: PASSED");
            serverThread.join(1000);
        }

        @Test
        public void testActAsSenderInvalidReceiverKey() throws Exception {
            System.out.println("[TEST] testActAsSenderInvalidReceiverKey: Starting test...");
            System.out.println("[TEST] testActAsSenderInvalidReceiverKey: Expecting exception for nonexistent receiver...");
            try {
                System.out.println("[TEST] testActAsSenderInvalidReceiverKey: Attempting to send data to nonexistent receiver...");
                ApiCalls.actAsSender("localhost", 12345, entityTypeA, clientNumA, "nonexistent", "DATA".getBytes());
                fail("Expected exception for invalid receiver key");
            } catch (Exception e) {
                System.out.println("[TEST] testActAsSenderInvalidReceiverKey: Caught expected exception: " + e.getMessage());
            }
            System.out.println("[TEST] testActAsSenderInvalidReceiverKey: PASSED");
        }


        @Test
        public void testSessionTerminationProtocol() throws Exception {
            System.out.println("[TEST] testSessionTerminationProtocol: Setting up SSLServerSocket with server's keystore and truststore...");
            java.security.KeyStore serverKeyStore = com.chainofproduct.utils.Cerificates.getKeystore(entityB, password);
            java.security.KeyStore serverTrustStore = com.chainofproduct.utils.Cerificates.getTruststore(entityB, password);
            System.out.println("[TEST] testSessionTerminationProtocol: Initializing KeyManagerFactory and TrustManagerFactory...");
            javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509");
            kmf.init(serverKeyStore, password.toCharArray());
            javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance("SunX509");
            tmf.init(serverTrustStore);
            System.out.println("[TEST] testSessionTerminationProtocol: Initializing SSLContext...");
            javax.net.ssl.SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());
            javax.net.ssl.SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
            javax.net.ssl.SSLServerSocket serverSocket = (javax.net.ssl.SSLServerSocket) ssf.createServerSocket(0);
            int port = serverSocket.getLocalPort();
            System.out.println("[TEST] testSessionTerminationProtocol: Server listening on port " + port);
            Thread serverThread = new Thread(() -> {
                System.out.println("[TEST] testSessionTerminationProtocol: Server thread started, waiting for client...");
                try (Socket client = serverSocket.accept()) {
                    System.out.println("[TEST] testSessionTerminationProtocol: Client connected, handling request...");
                    ApiCalls.handleClient(client, request -> null); // null triggers TERMINATE
                } catch (Exception e) {}
                System.out.println("[TEST] testSessionTerminationProtocol: Server thread finished.");
            });
            serverThread.start();
            Thread.sleep(100);
            System.out.println("[TEST] testSessionTerminationProtocol: Sending data for session termination test...");
            byte[] result = ApiCalls.actAsSender("localhost", port, entityTypeA, clientNumA, entityB, "DATA".getBytes());
            System.out.println("[TEST] testSessionTerminationProtocol: Received result: " + (result == null ? "null" : new String(result)));
            assertNull(result); // Should be null for TERMINATE
            System.out.println("[TEST] testSessionTerminationProtocol: PASSED");
            serverThread.join(1000);
        }

        // Additional edge case tests can be added for tampered payload, invalid session key, etc.
}
