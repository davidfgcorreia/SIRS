package com.chainofproduct.server;

import com.chainofproduct.utils.CryptoUtils;
import com.chainofproduct.utils.KeyTransmission;


public class Main {
    

    public static void main(String[] args) throws Exception {
        
        String serverName = "server";
        System.out.println("Generating keys...");
        com.chainofproduct.utils.Cerificates.main(new String[]{serverName});


        // Start EC keypair and key exchange listener using KeyTransmission (utils package)
        KeyTransmission keyTransmission = new KeyTransmission();
        Thread ecKeyExchangeThread = new Thread(() -> {
            try {
                // Use serverName as storePrefix, and resolve port for key exchange
                System.out.println("Starting EC key exchange listener...");
                com.chainofproduct.utils.ResolveDestinations.DestinationInfo destInfo = 
                    com.chainofproduct.utils.ResolveDestinations.resolve(serverName);
                int keyExchangePort = destInfo.certPort;
                keyTransmission.ensureECKeyAndStartListener(serverName, keyExchangePort);
                System.out.println("EC key exchange listener started on port " + keyExchangePort);
            } catch (Exception e) {
                System.err.println("Failed to start EC key exchange listener: " + e.getMessage());
                e.printStackTrace();
            }
        }, "ECKeyExchangeListener");
        ecKeyExchangeThread.setDaemon(true);
        ecKeyExchangeThread.start();
        
        // Initialize CryptoUtils to ensure replay-protection timer and nonce map are started
        try {
            System.out.println("Initializing CryptoUtils...");
            CryptoUtils.generateNonce();
            System.out.println("CryptoUtils initialized (replay protection active)");
        } catch (Throwable t) {
            System.err.println("Failed to initialize CryptoUtils: " + t.getMessage());
        }

        // Exchange certificates with database if needed
        try {
            System.out.println("Checking certificate exchange with database...");
            // Load database connection info from config
            com.chainofproduct.utils.ResolveDestinations.DestinationInfo dbInfo = 
            com.chainofproduct.utils.ResolveDestinations.resolve("db");
            
            com.chainofproduct.utils.Cerificates.verifyCertificaAndObtain(
                serverName,     // myEntityName: "server"
                "db",           // receiverName: database
                dbInfo.ip,      // receiverIp
                dbInfo.certPort // receiverPort (certificate exchange port)
            );
            System.out.println("Certificate exchange with database completed");
        } catch (Exception e) {
            System.err.println("Certificate exchange with database failed: " + e.getMessage());
            e.printStackTrace();
        }

        // Create ServerOperations to handle requests
        final ServerOperations serverOps = new ServerOperations();

        // Setup TLS socket and thread pool
        TLSServerListener.startListener(serverName, serverOps, keyTransmission);

        // Wait for EC key exchange thread to finish before exiting
        ecKeyExchangeThread.join();

        
    }
    
    /**
     * Gets configuration value from environment variable or returns default.
     */
    public static String getEnvOrDefault(String envVar, String defaultValue) {
        String value = System.getenv(envVar);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
    
    
}