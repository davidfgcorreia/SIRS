package com.chainofproduct.client;

import com.chainofproduct.utils.KeyTransmission;

public class ClientMain {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java ClientMain <companyName>");
            System.exit(1);
        }
        // Join all args with space to handle company names with spaces
        String companyName = String.join(" ", args);

        // Shared queue and lock for sending requests (if needed)
        java.util.concurrent.BlockingQueue<com.chainofproduct.utils.Request> sendQueue = new java.util.concurrent.LinkedBlockingQueue<>();
        Object sendLock = new Object();

        // Start EC keypair and key exchange listener using KeyTransmission (utils package)
        KeyTransmission keyTransmission = new KeyTransmission();
        try {
            // Use companyName as storePrefix, and resolve port for key exchange
            
            com.chainofproduct.utils.ResolveDestinations.DestinationInfo destInfo = com.chainofproduct.utils.ResolveDestinations.resolve(companyName);
            int keyExchangePort = destInfo.certPort;
            keyTransmission.ensureECKeyAndStartListener(companyName, keyExchangePort);
        } catch (Exception e) {
            System.err.println("Failed to start EC key exchange listener: " + e.getMessage());
        }

        // Start the send manager thread (if needed for direct communication)
        SendManager sendManager = new SendManager(sendQueue, sendLock);
        Thread sendManagerThread = new Thread(sendManager);
        sendManagerThread.setDaemon(true);
        sendManagerThread.start();

        // Pass companyName to operations/CLI
        ClientOperations operations = new ClientOperations(sendQueue, sendLock, companyName);

        

        int signaturePort=0;
        try {
            com.chainofproduct.utils.ResolveDestinations.DestinationInfo destInfo = com.chainofproduct.utils.ResolveDestinations.resolve(companyName);
            if (destInfo != null) {
                signaturePort = destInfo.port;
            }
        } catch (Exception e) {
            System.err.println("Failed to resolve port for " + companyName + ": " + e.getMessage());
        }
        SignatureRequestListener sigListener = new SignatureRequestListener(operations, signaturePort);
        sigListener.start();

        CommandLine cli = new CommandLine(operations);
        cli.run();

        // Shutdown send manager
        sendManager.stop();
        sigListener.stop();
        keyTransmission.closeKeyExchangeListener();



        try {
            sendManagerThread.join(1000);
        } catch (InterruptedException ignored) {}
    }
}
