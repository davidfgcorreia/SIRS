package com.chainofproduct.client;

import com.chainofproduct.utils.CryptoUtils;
import com.chainofproduct.utils.KeyTransmission;


public class ClientMain {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java ClientMain <companyName>");
            System.exit(1);
        }
        // Join all args with space to handle company names with spaces
        String companyName = String.join(" ", args);

        // Ensure certificates and public keys are available
        com.chainofproduct.utils.Cerificates.main(new String[]{companyName});

        // Start EC keypair and key exchange listener using KeyTransmission (utils package)
        KeyTransmission keyTransmission = new KeyTransmission();
        Thread keyExchangeThread = new Thread(() -> {
            try {
                // Use companyName as storePrefix, and resolve port for key exchange
                com.chainofproduct.utils.ResolveDestinations.DestinationInfo destInfo = com.chainofproduct.utils.ResolveDestinations.resolve(companyName);
                int keyExchangePort = destInfo.certPort;
                keyTransmission.ensureECKeyAndStartListener(companyName, keyExchangePort);
            } catch (Exception e) {
                System.err.println("Failed to start EC key exchange listener: " + e.getMessage());
            }
        });
        keyExchangeThread.setDaemon(true);
        keyExchangeThread.start();

         // Initialize CryptoUtils to ensure replay-protection timer and nonce map are started
        try {
            System.out.println("Initializing CryptoUtils...");
            CryptoUtils.generateNonce();
            System.out.println("CryptoUtils initialized (replay protection active)");
        } catch (Throwable t) {
            System.err.println("Failed to initialize CryptoUtils: " + t.getMessage());
        }

        // Shared queue and lock for sending requests
        java.util.concurrent.BlockingQueue<com.chainofproduct.utils.Request> sendQueue = new java.util.concurrent.LinkedBlockingQueue<>();
        Object sendLock = new Object();

        // Start the send manager thread
        SendManager sendManager = new SendManager(sendQueue, sendLock);
        sendManager.start();

        // Pass companyName to operations/CLI
        ClientOperations operations = new ClientOperations(sendQueue, sendLock, companyName);

        

        int signaturePort = 0;
        try {
            com.chainofproduct.utils.ResolveDestinations.DestinationInfo destInfo = com.chainofproduct.utils.ResolveDestinations.resolve(companyName);
            if (destInfo != null) {
                signaturePort = destInfo.signaturePort;
            }
        } catch (Exception e) {
            System.err.println("Failed to resolve port for " + companyName + ": " + e.getMessage());
        }


        SignatureRequestListener sigListener = new SignatureRequestListener(operations, signaturePort);
        sigListener.start();

        CommandLine cli = new CommandLine(operations);
        cli.run();

        // Shutdown listeners and threads
        sendManager.stop();
        sigListener.stop();
        keyTransmission.closeKeyExchangeListener();

        try {
            sendManager.join(1000);
            sigListener.join(1000);
            keyExchangeThread.join(1000);
        } catch (InterruptedException ignored) {}
    }
}
