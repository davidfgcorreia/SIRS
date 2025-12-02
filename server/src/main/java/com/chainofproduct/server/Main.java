package com.chainofproduct.server;

import com.chainofproduct.utils.ApiCalls;
import com.chainofproduct.utils.CryptoUtils;

public class Main {
    public static void main(String[] args) throws Exception {
        // Initialize server
        System.out.println("Starting Central Server...");
        
        // Ensure server keys exist before starting
        ensureKeysExist("server");
        
        // Initialize CryptoUtils to ensure replay-protection timer and nonce map are started
        try {
            CryptoUtils.generateNonce();
            System.out.println("CryptoUtils initialized (replay protection active).");
        } catch (Throwable t) {
            System.err.println("Warning: failed to initialize CryptoUtils: " + t.getMessage());
        }

        // Create ServerOperations to handle requests
        final ServerOperations serverOps = new ServerOperations();

        // Start TLS receiver thread - this is the ONLY communication channel now
        final int TLS_PORT = 8443;
        
        try (java.net.ServerSocket serverSocket = new java.net.ServerSocket(TLS_PORT)) {
            System.out.println("Central Server listening on port " + TLS_PORT + " - Ready for client connections");
            java.util.concurrent.ExecutorService receiverPool = java.util.concurrent.Executors.newFixedThreadPool(10);
            
            while (true) {
                final java.net.Socket socket = serverSocket.accept();
                receiverPool.submit(() -> {
                    try {
                        // Use custom executor to process requests and return responses
                        ApiCalls.handleClient(socket, (byte[] request) -> {
                            return serverOps.processRequest(request);
                        });
                    } catch (Exception e) {
                        System.err.println("Error handling client: " + e.getMessage());
                        e.printStackTrace();
                    }
                });
            }
        } catch (Exception e) {
            System.err.println("Fatal server error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Ensures RSA keypair exists for the server, generating if necessary.
     * This allows the server to automatically generate keys on first run.
     */
    private static void ensureKeysExist(String entityName) {
        java.io.File privateKeyFile = new java.io.File("keys/" + entityName + "-private.key");
        java.io.File publicKeyFile = new java.io.File("keys/" + entityName + "-public.key");
        
        if (privateKeyFile.exists() && publicKeyFile.exists()) {
            return;
        }
        
        System.out.println("Server keys not found. Generating new RSA-2048 keypair...");
        
        try {
            // Generate keypair using Java KeyPairGenerator
            java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // Create keys directory if it doesn't exist
            privateKeyFile.getParentFile().mkdirs();
            
            // Save private key in PKCS#8 DER format
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(privateKeyFile)) {
                fos.write(keyPair.getPrivate().getEncoded());
            }
            
            // Save public key in X.509 DER format
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(publicKeyFile)) {
                fos.write(keyPair.getPublic().getEncoded());
            }
            
            // Set permissions
            privateKeyFile.setReadable(true, true);
            privateKeyFile.setWritable(true, true);
            publicKeyFile.setReadable(true, false);
            
            System.out.println("✓ Server keys generated successfully");
        } catch (Exception e) {
            System.err.println("ERROR: Failed to generate server keys: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}