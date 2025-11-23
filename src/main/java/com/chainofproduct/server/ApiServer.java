package com.chainofproduct.server;

import java.io.*;
import javax.net.ssl.*;
import com.chainofproduct.CryptoUtils;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;;

public class ApiServer {

    // Sender logic: initiates handshake, receives session keys, sends encrypted data
    public static void actAsSender(String host, int port, String privKeyFile, String receiverPubKeyFile, String dataFile) throws Exception {
        // Load keys
        PrivateKey senderPrivateKey = loadPrivateKey(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(privKeyFile)));
        PublicKey receiverPublicKey = loadPublicKey(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(receiverPubKeyFile)));
        // Connect
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) sf.createSocket(host, port)) {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());
            // --- 1. Handshake: send nonce, timestamp, signature, public key ---
            byte[] nonce = new byte[8];
            new java.security.SecureRandom().nextBytes(nonce);
            long timestamp = System.currentTimeMillis();
            byte[] toSign = new byte[nonce.length + 8];
            System.arraycopy(nonce, 0, toSign, 0, nonce.length);
            for (int i = 0; i < 8; i++) toSign[nonce.length + i] = (byte) (timestamp >>> (8 * (7 - i)));
            byte[] signature = asymmetricSign(toSign, senderPrivateKey);
            out.write(nonce);
            out.writeLong(timestamp);
            out.writeInt(signature.length);
            out.write(signature);
            byte[] senderPubBytes = receiverPublicKey.getEncoded(); // For demo, use receiver's pubkey as sender's pubkey
            out.writeInt(senderPubBytes.length);
            out.write(senderPubBytes);
            out.flush();
            // --- 2. Wait for AUTH_OK ---
            String authResp = in.readUTF();
            if (!"AUTH_OK".equals(authResp)) {
                System.err.println("Authentication failed: " + authResp);
                return;
            }
            // --- 3. Receive session keys ---
            int sessLen = in.readInt();
            byte[] encryptedSessionKeys = new byte[sessLen];
            in.readFully(encryptedSessionKeys);
            byte[] sessionKeys = asymmetricDecrypt(encryptedSessionKeys, senderPrivateKey, receiverPublicKey);
            byte[] aesKeyBytes = new byte[32];
            byte[] hmacKeyBytes = new byte[32];
            System.arraycopy(sessionKeys, 0, aesKeyBytes, 0, 32);
            System.arraycopy(sessionKeys, 32, hmacKeyBytes, 0, 32);
            SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
            SecretKey hmacKey = new javax.crypto.spec.SecretKeySpec(hmacKeyBytes, "HmacSHA256");
            // --- 4. Encrypt and send data ---
            byte[] data = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(dataFile));
            String encryptedData = CryptoUtils.encrypt(data, aesKey, hmacKey);
            out.writeUTF("SEND_TRANSACTION");
            byte[] encBytes = encryptedData.getBytes();
            out.writeInt(encBytes.length);
            out.write(encBytes);
            out.flush();
            // --- 5. Wait for ACK ---
            String ack = in.readUTF();
            System.out.println("Server response: " + ack);
        }
    }

    // Helper: sign data with private key (for handshake)
    private static byte[] asymmetricSign(byte[] data, PrivateKey priv) throws Exception {
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(priv);
        sig.update(data);
        return sig.sign();
    }

    // New handleClient: expects encrypted byte[] data, port, ip, sender's private key, receiver's public key
    public static void handleClient(SSLSocket socket) throws Exception {
        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            // --- 1. Handshake: Sender authenticates with signed nonce/timestamp ---
            byte[] nonce = new byte[8];
            in.readFully(nonce);
            long timestamp = in.readLong();
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);
            int pubLen = in.readInt();
            byte[] senderPubBytes = new byte[pubLen];
            in.readFully(senderPubBytes);
            PublicKey senderPublicKey = loadPublicKey(senderPubBytes);

            // Verify signature and freshness
            boolean authOK = verifySignatureAndFreshness(nonce, timestamp, signature, senderPublicKey);
            if (!authOK) {
                out.writeUTF("AUTH_FAIL");
                out.flush();
                return;
            }
            out.writeUTF("AUTH_OK");
            out.flush();

            // --- 2. Receiver generates session keys and sends them encrypted with sender's public key ---
            SecretKey aesKey = CryptoUtils.generateAESKey(256);
            SecretKey hmacKey = CryptoUtils.generateHMACKey();
            byte[] aesKeyBytes = aesKey.getEncoded();
            byte[] hmacKeyBytes = hmacKey.getEncoded();
            byte[] sessionKeys = new byte[aesKeyBytes.length + hmacKeyBytes.length];
            System.arraycopy(aesKeyBytes, 0, sessionKeys, 0, aesKeyBytes.length);
            System.arraycopy(hmacKeyBytes, 0, sessionKeys, aesKeyBytes.length, hmacKeyBytes.length);
            byte[] encryptedSessionKeys = asymmetricEncrypt(sessionKeys, senderPublicKey, null);
            out.writeInt(encryptedSessionKeys.length);
            out.write(encryptedSessionKeys);
            out.flush();

            // --- 3. Sender encrypts and sends data using session keys ---
            String command = in.readUTF();
            int payloadLen = in.readInt();
            byte[] encryptedPayload = new byte[payloadLen];
            in.readFully(encryptedPayload);
            byte[] decryptedPayload = CryptoUtils.decrypt(new String(encryptedPayload), aesKey, hmacKey, 5 * 60 * 1000);

            // --- 4. Receiver processes data and sends ACK ---
            switch (command) {
                case "SEND_TRANSACTION":
                case "SEND_SHARE":
                    // Store/process decryptedPayload as needed
                    System.out.println("Received command: " + command);
                    System.out.println("Decrypted payload: " + new String(decryptedPayload));
                    out.writeUTF("ACK");
                    out.flush();
                    break;
                default:
                    out.writeUTF("ERROR: Unknown command");
                    out.flush();
            }
        } finally {
            // Cleanly close session
            try { socket.close(); } catch (Exception ignore) {}
        }
    }

    // Helper: verify signature and freshness
    private static boolean verifySignatureAndFreshness(byte[] nonce, long timestamp, byte[] signature, PublicKey senderPublicKey) throws Exception {
        long now = System.currentTimeMillis();
        if (Math.abs(now - timestamp) > 5 * 60 * 1000) return false; // 5 min window
        // Verify signature using sender's public key
        byte[] toVerify = new byte[nonce.length + 8];
        System.arraycopy(nonce, 0, toVerify, 0, nonce.length);
        for (int i = 0; i < 8; i++) toVerify[nonce.length + i] = (byte) (timestamp >>> (8 * (7 - i)));
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initVerify(senderPublicKey);
        sig.update(toVerify);
        return sig.verify(signature);
    }

    // Helper: load private key from PKCS8 bytes
    private static PrivateKey loadPrivateKey(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    // Helper: load public key from X509 bytes
    private static PublicKey loadPublicKey(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
    // Helper: asymmetric decrypt (for demo, just return input; replace with real RSA decryption)
    private static byte[] asymmetricDecrypt(byte[] data, PrivateKey priv, PublicKey pub) throws Exception {
        // Decrypt with private key (RSA/ECB/PKCS1Padding)
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, priv);
        return cipher.doFinal(data);
    }
    // Helper: asymmetric encrypt (for demo, just return input; replace with real RSA encryption)
    private static byte[] asymmetricEncrypt(byte[] data, PublicKey pub, PrivateKey priv) throws Exception {
        // Encrypt with public key (RSA/ECB/PKCS1Padding)
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(data);
    }
// (Old unreachable code removed)
}
