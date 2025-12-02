package com.chainofproduct.utils;

import java.io.*;
import java.net.*;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;;

public class ApiCalls {

    // Sender logic: initiates handshake, receives session keys, sends encrypted data with HMAC
    public static byte[] actAsSender(String host, int port, String senderPrivKeyFile, String senderPubKeyFile, String receiverPubKeyFile, byte[] dataFile) throws Exception {
        // Load sender's private and public key
        PrivateKey senderPrivateKey = loadPrivateKey(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(senderPrivKeyFile)));
        PublicKey senderPublicKey = loadPublicKey(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(senderPubKeyFile)));
        // Load receiver's public key
        PublicKey receiverPublicKey = loadPublicKey(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(receiverPubKeyFile)));

        byte[] result = null;
        try (Socket socket = new Socket(host, port)) {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());
            // --- 1. Handshake: send nonce, timestamp, signature, sender's public key ---
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
            byte[] senderPubBytes = senderPublicKey.getEncoded();
            out.writeInt(senderPubBytes.length);
            out.write(senderPubBytes);
            out.flush();
            // --- 2. Wait for AUTH_OK ---
            String authResp = in.readUTF();
            if (!"AUTH_OK".equals(authResp)) {
                System.err.println("Authentication failed: " + authResp);
                return null;
            }
            // --- 3. Receive session keys ---
            int sessLen = in.readInt();
            byte[] encryptedSessionKeys = new byte[sessLen];
            in.readFully(encryptedSessionKeys);
            byte[] sessionKeys = asymmetricDecrypt(encryptedSessionKeys, senderPrivateKey, receiverPublicKey);
            byte[] aesKeyBytes = new byte[32];
            System.arraycopy(sessionKeys, 0, aesKeyBytes, 0, 32);
            SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
            // --- 4. Encrypt and send data ---
            byte[] encryptedData = CryptoUtils.encrypt(dataFile, aesKey);
            out.writeInt(encryptedData.length);
            out.write(encryptedData);
            out.flush();
            // --- 5. Wait for server response: could be TERMINATE or encrypted data ---
            String serverMsg = in.readUTF();
            if ("TERMINATE".equals(serverMsg)) {
                // Server wants to end connection (no response data)
                out.writeUTF("ACK");
                out.flush();
                String terminateAck = in.readUTF();
                if ("TERMINATE_ACK".equals(terminateAck)) {
                    System.out.println("Session terminated by server.");
                }
                return null;
            } else if ("ERROR:".equals(serverMsg.substring(0, Math.min(6, serverMsg.length())))) {
                // Server sent error message
                System.err.println("Server error: " + serverMsg);
                return null;
            }
            
            // Server has data - read encrypted response
            int respLen = in.readInt();
            byte[] encryptedResponse = new byte[respLen];
            in.readFully(encryptedResponse);
            byte[] decryptedResponse = CryptoUtils.decrypt(encryptedResponse, aesKey, 5 * 60 * 1000);
            if (decryptedResponse == null) {
                System.err.println("Failed to decrypt server response");
                return null;
            }
            result = decryptedResponse;
            
            // Send ACK and wait for termination
            out.writeUTF("ACK");
            out.flush();
            String terminateAck = in.readUTF();
            if ("TERMINATE_ACK".equals(terminateAck)) {
                System.out.println("Session terminated after receiving response.");
            }
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
            byte[] aesKeyBytes = aesKey.getEncoded();
            byte[] sessionKeys = aesKeyBytes; // Only AES key needed now
            byte[] encryptedSessionKeys = asymmetricEncrypt(sessionKeys, senderPublicKey, null);
            out.writeInt(encryptedSessionKeys.length);
            out.write(encryptedSessionKeys);
            out.flush();

            // --- 3. Receive encrypted data ---
            int payloadLen = in.readInt();
            byte[] encryptedPayload = new byte[payloadLen];
            in.readFully(encryptedPayload);
            byte[] decryptedPayload = CryptoUtils.decrypt(encryptedPayload, aesKey, 5 * 60 * 1000);
            if (decryptedPayload == null) {
                out.writeUTF("ERROR: Decryption failed");
                out.flush();
                return;
            }

            // --- 4. Call server executor ---
            byte[] response = executor.execute(decryptedPayload);
            if (response == null) {
                // No response: terminate session
                out.writeUTF("TERMINATE");
                out.flush();
                String ack = in.readUTF();
                if ("ACK".equals(ack)) {
                    out.writeUTF("TERMINATE_ACK");
                    out.flush();
                }
                return;
            } else {
                // Signal that we have data, then encrypt and send response
                out.writeUTF("DATA");
                out.flush();
                byte[] encryptedResponse = CryptoUtils.encrypt(response, aesKey);
                out.writeInt(encryptedResponse.length);
                out.write(encryptedResponse);
                out.flush();
                String ack = in.readUTF();
                if ("ACK".equals(ack)) {
                    out.writeUTF("TERMINATE_ACK");
                    out.flush();
                }
            }
        } finally {
            try { socket.close(); } catch (Exception ignore) {}
        }
    }

        // Helper: sign data with private key (for handshake)
    private static byte[] asymmetricSign(byte[] data, PrivateKey priv) throws Exception {
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(priv);
        sig.update(data);
        return sig.sign();
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
