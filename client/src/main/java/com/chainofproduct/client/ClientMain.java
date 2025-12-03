package com.chainofproduct.client;

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

        // Start the send manager thread (if needed for direct communication)
        SendManager sendManager = new SendManager(sendQueue, sendLock);
        Thread sendManagerThread = new Thread(sendManager);
        sendManagerThread.setDaemon(true);
        sendManagerThread.start();

        // Pass companyName to operations/CLI
        ClientOperations operations = new ClientOperations(sendQueue, sendLock, companyName);
        CommandLine cli = new CommandLine(operations);
        cli.run();

        // Shutdown send manager
        sendManager.stop();
        try {
            sendManagerThread.join(1000);
        } catch (InterruptedException ignored) {}
    }
}
