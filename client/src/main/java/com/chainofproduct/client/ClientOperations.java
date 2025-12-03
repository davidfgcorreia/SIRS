package com.chainofproduct.client;

import java.util.concurrent.BlockingQueue;

import com.chainofproduct.utils.Request;

public class ClientOperations {
    private final BlockingQueue<Request> sendQueue;
    private final Object sendLock;
    private final String clientName;
    private final String entityType;
    private final int clientNum;
    private final String receiverEntity;
    private final String serverHost;
    private final int serverPort;

    public ClientOperations(BlockingQueue<Request> sendQueue, Object sendLock, String clientName) {
        this.sendQueue = sendQueue;
        this.sendLock = sendLock;
        this.clientName = clientName;
        this.entityType = "client";
        this.clientNum = parseClientNum(clientName);
        this.receiverEntity = "server";
        String host = null;
        int port = 0;
        try {
            java.nio.file.Path infoPath = java.nio.file.Paths.get("localization_info/server_info.json");
            String json = new String(java.nio.file.Files.readAllBytes(infoPath), java.nio.charset.StandardCharsets.UTF_8);
            host = extractJsonStringField(json, "ip");
            String portStr = extractJsonStringField(json, "port");
            if (portStr != null && !portStr.isEmpty()) {
                port = Integer.parseInt(portStr);
            }
        } catch (Exception e) {
            System.err.println("Failed to load server info from localizationinfo/serverinfo.json: " + e.getMessage());
        }
        this.serverHost = host;
        this.serverPort = port;
    }

    
    // Enqueue a transaction send request (Type 1)
    public void sendtrsaction(String dataFile, String destination) {
        String payload = "{request_type: transaction, source: " + this.clientName + ", destination: " + destination + "}";
        byte[] fileBytes = null;
        try {
            java.nio.file.Path path = java.nio.file.Paths.get(dataFile);
            fileBytes = java.nio.file.Files.readAllBytes(path);
        } catch (Exception e) {
            System.err.println("Failed to read dataFile as bytes: " + e.getMessage());
            return;
        }
        byte[] payloadBytes = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] combined = new byte[payloadBytes.length + fileBytes.length];
        System.arraycopy(payloadBytes, 0, combined, 0, payloadBytes.length);
        System.arraycopy(fileBytes, 0, combined, payloadBytes.length, fileBytes.length);
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            combined
        );
        enqueueRequest(req);
        System.out.println("Enqueued transaction send request for " + destination);
    }

    // Enqueue a getById request (Type 3)
    public void gettransactionById(long id) {
        String payload = "{request_type:getById, servername: " + this.clientName +  ", trasaction_id: " + id + "}";
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        enqueueRequest(req);
        System.out.println("Enqueued getById request for id=" + id);
    }

    // Enqueue a getAll request (Type 4)
    public void getAll() {
        String payload = "{request_type:getAll, servername: " + this.clientName + "}";
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        enqueueRequest(req);
        System.out.println("Enqueued getAll request");
    }

    // Enqueue a getShares request (Type 5)
    public void getShares(long tid) {
        String payload = "{request_type:getShares, servername: " + this.clientName + ", transaction_id: " + tid + "}";
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        enqueueRequest(req);
        System.out.println("Enqueued getShares request for tid=" + tid);
    }

    // Enqueue a getSharesBy request (Type 6)
    public void getSharesBy(long tid, String sharedBy) {
        String payload = "{request_type:getSharesBy, servername: " + this.clientName + ", transaction_id: " + tid + ", shared_by: " + sharedBy + "}";
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        enqueueRequest(req);
        System.out.println("Enqueued getSharesBy request for tid=" + tid + ", sharedBy=" + sharedBy);
    }

        // Enqueue a getRecentTransactions request (Type 7)
    public void getRecentTransactionsSince(long sinceTimestamp) {
        String payload = "{request_type:getRecentTransactions, servername: " + this.clientName + ", since: " + sinceTimestamp + "}";
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        enqueueRequest(req);
        System.out.println("Enqueued getRecentTransactions request since timestamp=" + sinceTimestamp);
    }




    // Helper to enqueue and notify send manager
    private void enqueueRequest(Request req) {
        try {
            sendQueue.put(req);
            synchronized (sendLock) {
                sendLock.notifyAll();
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            System.err.println("enqueueRequest interrupted: " + ie.getMessage());
        }
    }


    



    /**
     * Verifies if a received file was not tampered with, using only this client's public key.
     * Determines role (seller/buyer) by parsing the JSON and comparing clientName.
     * Expects decryptedBytes in the format:
     *   {request_type:transaction, destination:...}<json file> <seller_signature> <buyer_signature>
     * Returns true if the relevant signature is valid for the file, false otherwise.
     */
    public boolean verifyFileIntegrity(String dataFilePath) {
        try {
            // Read the file bytes
            java.nio.file.Path path = java.nio.file.Paths.get(dataFilePath);
            byte[] completfileBytes = java.nio.file.Files.readAllBytes(path);

            // 1. Extract payload, file, and signatures
            String asString = new String(completfileBytes, java.nio.charset.StandardCharsets.UTF_8);
            int payloadEnd = asString.indexOf('}') + 1;
            if (payloadEnd <= 0) return false;
            int sigLen = 344;
            int buyerSigStart = completfileBytes.length - sigLen;
            int sellerSigStart = buyerSigStart - sigLen;
            if (sellerSigStart <= payloadEnd) return false;
            byte[] fileBytes = java.util.Arrays.copyOfRange(completfileBytes, payloadEnd, sellerSigStart);
            String sellerSigB64 = new String(java.util.Arrays.copyOfRange(completfileBytes, sellerSigStart, buyerSigStart), java.nio.charset.StandardCharsets.UTF_8);
            String buyerSigB64 = new String(java.util.Arrays.copyOfRange(completfileBytes, buyerSigStart, completfileBytes.length), java.nio.charset.StandardCharsets.UTF_8);
            // 2. Parse the JSON to determine role (manual string extraction)
            String jsonString = new String(fileBytes, java.nio.charset.StandardCharsets.UTF_8);
            int jsonEnd = jsonString.indexOf('}') + 1;
            if (jsonEnd <= 0) return false;
            String jsonPart = jsonString.substring(0, jsonEnd);
            String role = null;
            String seller = extractJsonStringField(jsonPart, "seller");
            String buyer = extractJsonStringField(jsonPart, "buyer");
            if (seller == null) seller = "";
            if (buyer == null) buyer = "";
            if (clientName.equalsIgnoreCase(seller)) {
                role = "seller";
            } else if (clientName.equalsIgnoreCase(buyer)) {
                role = "buyer";
            } else {
                System.err.println("verifyFileIntegrity: clientName does not match seller or buyer");
                return false;
            }

            // 3. Compute hash of the file
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] fileHash = digest.digest(fileBytes);

            // 4. Load my public key from PKCS12 truststore-pubkeys
            java.security.PublicKey myPubKey = loadPublicKeyFromTruststore("keys/client-truststore-pubkeys.p12", this.clientName, "changeit");

            // 5. Verify the relevant signature
            if ("seller".equalsIgnoreCase(role)) {
                return verifySignature(fileHash, sellerSigB64, myPubKey);
            } else if ("buyer".equalsIgnoreCase(role)) {
                return verifySignature(fileHash, buyerSigB64, myPubKey);
            } else {
                System.err.println("verifyFileIntegrity: unknown role '" + role + "'");
                return false;
            }
        } catch (Exception e) {
            System.err.println("verifyFileIntegrity error: " + e.getMessage());
            return false;
        }
    }


    // Helper to load a public key from PKCS12 truststore-pubkeys
    private java.security.PublicKey loadPublicKeyFromTruststore(String truststorePath, String alias, String password) throws Exception {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(truststorePath)) {
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            ks.load(fis, password.toCharArray());
            java.security.cert.Certificate cert = ks.getCertificate(alias);
            if (cert == null) {
                throw new java.security.KeyStoreException("No certificate found for alias: " + alias);
            }
            return cert.getPublicKey();
        }
    }

    // Helper to verify a signature
    private boolean verifySignature(byte[] data, String signatureB64, java.security.PublicKey pubKey) throws Exception {
        byte[] sigBytes = java.util.Base64.getDecoder().decode(signatureB64);
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(data);
        return sig.verify(sigBytes);
    }

    // Helper to extract client number from clientName (e.g., "client42" -> 42)
    private int parseClientNum(String clientName) {
        String digits = clientName.replaceAll("\\D+", "");
        if (digits.isEmpty()) return 0;
        return Integer.parseInt(digits);
    }

            // Helper to extract a string field from a simple JSON object (no nested objects)
    private String extractJsonStringField(String json, String field) {
            String key = "\"" + field + "\":";
            int idx = json.indexOf(key);
            if (idx == -1) return null;
            int start = json.indexOf('"', idx + key.length());
            int end = json.indexOf('"', start + 1);
            if (start == -1 || end == -1) return null;
            return json.substring(start + 1, end);
        }

    

}
