package com.chainofproduct.server;

import com.chainofproduct.db.DatabaseOperations;
import com.chainofproduct.utils.ApiCalls;
import com.chainofproduct.utils.CryptoUtils;

public class Main {
    public static void main(String[] args) throws Exception {
        // SET SERVER IDENTITY - This is the CENTRAL SERVER that all clients connect to
        // Default: "Central Server" (neutral mediator between all companies)
        // Can be overridden via: -Dserver.name="Custom Name"
        String serverIdentity = System.getProperty("server.name", "Central Server");
        DatabaseOperations.setServerName(serverIdentity);
        System.out.println("Server identity set to: " + serverIdentity);
        
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
}