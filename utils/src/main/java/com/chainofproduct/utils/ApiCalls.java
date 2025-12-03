package com.chainofproduct.utils;

import java.io.*;
import java.net.*;
import javax.crypto.SecretKey;

public class ApiCalls {
    // Replay protection for session key exchange
    private static final java.util.concurrent.ConcurrentMap<String, Long> usedNonces = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.Timer nonceCleanupTimer = new java.util.Timer(true);
    static {
        nonceCleanupTimer.schedule(new java.util.TimerTask() {
            @Override
            public void run() {
                long now = System.currentTimeMillis();
                usedNonces.entrySet().removeIf(e -> e.getValue() < now);
            }
        }, 60_000, 60_000); // every 1 minute
    }

    // Sender logic: initiates handshake, receives session keys, sends encrypted data
    public static byte[] actAsSender(String host, int port, String entityType, int clientNum, String receiverEntity, byte[] dataFile) throws Exception {
        // Load receiver's public RSA key from PKCS12 truststore-pubkeys
        String pubKeyTruststorePath = receiverEntity + "-truststore-pubkeys.p12";
        java.security.KeyStore pubKeyStore = java.security.KeyStore.getInstance("PKCS12");
        try (FileInputStream pubKeyFis = new FileInputStream(pubKeyTruststorePath)) {
            pubKeyStore.load(pubKeyFis, "changeit".toCharArray());
        }
        java.security.cert.Certificate pubKeyCert = pubKeyStore.getCertificate(receiverEntity + "-pubkey");
        java.security.PublicKey receiverPubKey = pubKeyCert.getPublicKey();
        // Determine keystore/truststore paths based on entity type
        String alias, keyStorePath, trustStorePath;
        if ("client".equalsIgnoreCase(entityType)) {
            alias = "client" + clientNum;
            keyStorePath = alias + "-keystore.p12";
            trustStorePath = alias + "-truststore.p12";
        } else if ("server".equalsIgnoreCase(entityType)) {
            alias = "server";
            keyStorePath = "server-keystore.p12";
            trustStorePath = "server-truststore.p12";
        } else if ("db".equalsIgnoreCase(entityType)) {
            alias = "db";
            keyStorePath = "db-keystore.p12";
            trustStorePath = "db-truststore.p12";
        } else {
            throw new IllegalArgumentException("Unknown entity type: " + entityType);
        }
        String keyStorePassword = "changeit";
        String trustStorePassword = "changeit";

        // Load sender's private and public key from keystore
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        try (FileInputStream keyStoreFis = new FileInputStream(keyStorePath)) {
            keyStore.load(keyStoreFis, keyStorePassword.toCharArray());
        }
        // Load sender's private key from keystore (for TLS mutual auth)
        // Load truststore (for TLS mutual auth)
        java.security.KeyStore trustStore = java.security.KeyStore.getInstance("PKCS12");
        try (FileInputStream trustStoreFis = new FileInputStream(trustStorePath)) {
            trustStore.load(trustStoreFis, trustStorePassword.toCharArray());
        }

        javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, keyStorePassword.toCharArray());
        javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);
        javax.net.ssl.SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());
        javax.net.ssl.SSLSocketFactory factory = sslContext.getSocketFactory();

        byte[] result = null;
        try (Socket socket = factory.createSocket(host, port)) {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());
            if (socket instanceof javax.net.ssl.SSLSocket) {
                ((javax.net.ssl.SSLSocket) socket).startHandshake();
            }
            // 1. Generate a new random session AES key
            javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey sessionKey = keyGen.generateKey();
            // 1b. Add timestamp and nonce for replay/freshness protection
            long timestamp = java.time.Instant.now().toEpochMilli();
            byte[] nonce = com.chainofproduct.utils.CryptoUtils.generateNonce();
            byte[] sessionKeyBytes = sessionKey.getEncoded();
            java.nio.ByteBuffer sessionKeyBuf = java.nio.ByteBuffer.allocate(8 + nonce.length + sessionKeyBytes.length);
            sessionKeyBuf.putLong(timestamp);
            sessionKeyBuf.put(nonce);
            sessionKeyBuf.put(sessionKeyBytes);
            byte[] sessionKeyWithMeta = sessionKeyBuf.array();
            // 2. Encrypt the session key+meta with the receiver's public RSA key and send it
            javax.crypto.Cipher rsaCipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(javax.crypto.Cipher.ENCRYPT_MODE, receiverPubKey);
            byte[] encSessionKey = rsaCipher.doFinal(sessionKeyWithMeta);
            if (encSessionKey.length <= 0 || encSessionKey.length > 4096) throw new IOException("Invalid session key length");
            out.writeInt(encSessionKey.length);
            out.write(encSessionKey);
            out.flush();
            // 3. Use the session key for all further encrypt/decrypt
            byte[] encryptedPayload = CryptoUtils.encrypt(dataFile, sessionKey);
            if (encryptedPayload.length <= 0 || encryptedPayload.length > 10_000_000) throw new IOException("Invalid payload length");
            out.writeInt(encryptedPayload.length);
            out.write(encryptedPayload);
            out.flush();
            // Wait for server response (could be TERMINATE or query result)
            int respLen = in.readInt();
            if (respLen <= 0 || respLen > 10_000_000) throw new IOException("Invalid response length");
            byte[] encryptedResp = new byte[respLen];
            in.readFully(encryptedResp);
            // Decrypt server response
            String serverMsg = new String(CryptoUtils.decrypt(encryptedResp, sessionKey, 5 * 60 * 1000), java.nio.charset.StandardCharsets.UTF_8);
            if ("TERMINATE".equals(serverMsg)) {
                out.writeUTF("ACK");
                out.flush();
                String terminateAck = null;
                try {
                    terminateAck = in.readUTF();
                } catch (EOFException eof) {
                    terminateAck = null;
                }
                if ("TERMINATE_ACK".equals(terminateAck)) {
                    System.out.println("Session terminated by server.");
                }
                return null;
            } else {
                result = serverMsg.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                out.writeUTF("ACK");
                out.flush();
                String terminateAck = null;
                try {
                    terminateAck = in.readUTF();
                } catch (EOFException eof) {
                    terminateAck = null;
                }
                if ("TERMINATE_ACK".equals(terminateAck)) {
                    System.out.println("Session terminated after query.");
                }
            }
        } catch (Exception e) {
            System.err.println("[SECURITY] Error in actAsSender: " + e.getMessage());
            throw e;
        }
        return result;
    }



    /**
     * ServerExecutor interface for server-specific request handling.
     */
    public interface ServerExecutor {
        /**
         * Process the decrypted request and return response bytes, or null to terminate.
         * @param request The decrypted request bytes
         * @return response bytes to send, or null to terminate
         */
        byte[] execute(byte[] request) throws Exception;
    }

    /**
     * handleClient: receives, decrypts, and dispatches request to a ServerExecutor.
     * Sends response or handles session termination protocol.
     */
    public static void handleClient(Socket socket, ServerExecutor executor) throws Exception {
        // Dynamically determine alias ("server" or "db") based on the certificate subject in the SSLSession
        String alias = null;
        if (socket instanceof javax.net.ssl.SSLSocket) {
            javax.net.ssl.SSLSocket sslSocket = (javax.net.ssl.SSLSocket) socket;
            sslSocket.startHandshake(); // Explicit handshake for security
            javax.net.ssl.SSLSession session = sslSocket.getSession();
            java.security.cert.Certificate[] certs = session.getLocalCertificates();
            if (certs != null && certs.length > 0 && certs[0] instanceof java.security.cert.X509Certificate) {
                String subject = ((java.security.cert.X509Certificate) certs[0]).getSubjectX500Principal().getName();
                if (subject.contains("CN=server")) {
                    alias = "server";
                } else if (subject.contains("CN=db")) {
                    alias = "db";
                }
            }
        }
        if (alias == null) alias = "server"; // fallback for non-SSL or unknown, default to server
        String keyStorePath = alias + "-keystore.p12";
        String keyStorePassword = "changeit";
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        try (FileInputStream keyStoreFis = new FileInputStream(keyStorePath)) {
            keyStore.load(keyStoreFis, keyStorePassword.toCharArray());
        }
        java.security.PrivateKey privateKey = (java.security.PrivateKey) keyStore.getKey(alias, keyStorePassword.toCharArray());
        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
            // 1. Receive the encrypted session key and decrypt it with RSA
            int encSessionKeyLen = in.readInt();
            if (encSessionKeyLen <= 0 || encSessionKeyLen > 4096) throw new IOException("Invalid session key length");
            byte[] encSessionKey = new byte[encSessionKeyLen];
            in.readFully(encSessionKey);
            javax.crypto.Cipher rsaCipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey);
            byte[] sessionKeyWithMeta = rsaCipher.doFinal(encSessionKey);
            // Validate timestamp and nonce for replay/freshness protection
            if (sessionKeyWithMeta.length < 8 + com.chainofproduct.utils.CryptoUtils.NONCE_LENGTH + 16) throw new SecurityException("Session key meta too short");
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(sessionKeyWithMeta);
            long timestamp = buf.getLong();
            byte[] nonce = new byte[com.chainofproduct.utils.CryptoUtils.NONCE_LENGTH];
            buf.get(nonce);
            byte[] sessionKeyBytes = new byte[sessionKeyWithMeta.length - 8 - com.chainofproduct.utils.CryptoUtils.NONCE_LENGTH];
            buf.get(sessionKeyBytes);
            long now = java.time.Instant.now().toEpochMilli();
            long maxAgeMillis = 5 * 60 * 1000;
            long clockDrift = 60 * 1000;
            if (timestamp < 0 || timestamp > now + clockDrift) throw new SecurityException("Session key timestamp invalid");
            if (now - timestamp > maxAgeMillis) throw new SecurityException("Session key too old");
            // Replay protection: check and store nonce
            String nonceKey = java.util.Base64.getEncoder().encodeToString(nonce);
            Long expires = usedNonces.putIfAbsent(nonceKey, now + maxAgeMillis + clockDrift);
            if (expires != null) throw new SecurityException("Session key replay detected");
            SecretKey sessionKey = new javax.crypto.spec.SecretKeySpec(sessionKeyBytes, "AES");
            // 2. Receive the encrypted payload and decrypt with session key
            int payloadLen = in.readInt();
            if (payloadLen <= 0 || payloadLen > 10_000_000) throw new IOException("Invalid payload length");
            byte[] encryptedPayload = new byte[payloadLen];
            in.readFully(encryptedPayload);
            byte[] payload = CryptoUtils.decrypt(encryptedPayload, sessionKey, 5 * 60 * 1000);
            // Call server executor
            byte[] response = executor.execute(payload);
            // Encrypt response with session key
            byte[] encryptedResp = CryptoUtils.encrypt(response == null ? "TERMINATE".getBytes(java.nio.charset.StandardCharsets.UTF_8) : response, sessionKey);
            out.writeInt(encryptedResp.length);
            out.write(encryptedResp);
            out.flush();
            // Session closing protocol
            String ack = null;
            try {
                ack = in.readUTF();
            } catch (EOFException eof) {
                // Client closed connection early
                ack = null;
            }
            if ("ACK".equals(ack)) {
                out.writeUTF("TERMINATE_ACK");
                out.flush();
            }
        } catch (Exception e) {
            // Log and propagate security errors
            System.err.println("[SECURITY] Error in handleClient: " + e.getMessage());
            throw e;
        } finally {
            try { socket.close(); } catch (Exception ignore) {}
        }
    }

// (Old unreachable code removed)
}
