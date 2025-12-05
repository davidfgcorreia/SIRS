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

        // Start EC key exchange listener for this client
        int certPort = 0;
        try {
            java.nio.file.Path portsPath = java.nio.file.Paths.get("localization_info/elemets_info.json");
            String portsJson = new String(java.nio.file.Files.readAllBytes(portsPath), java.nio.charset.StandardCharsets.UTF_8);
            int idx = portsJson.indexOf('"' + companyName + '"');
            if (idx != -1) {
                int portIdx = portsJson.indexOf("certport", idx);
                if (portIdx != -1) {
                    int colonIdx = portsJson.indexOf(':', portIdx);
                    int commaIdx = portsJson.indexOf(',', colonIdx);
                    int endIdx = commaIdx != -1 ? commaIdx : portsJson.indexOf('}', colonIdx);
                    String portStr = portsJson.substring(colonIdx + 1, endIdx).replaceAll("[^0-9]", "").trim();
                    certPort = Integer.parseInt(portStr);
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to read certport from client_ports.json: " + e.getMessage());
            throw new RuntimeException(e);

        }
        try {
            com.chainofproduct.utils.KeyTransmission.ensureECKeyAndStartListener(companyName, certPort);
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
        CommandLine cli = new CommandLine(operations);
        cli.run();

        // Shutdown send manager
        sendManager.stop();
        try {
            sendManagerThread.join(1000);
        } catch (InterruptedException ignored) {}
    }
}
