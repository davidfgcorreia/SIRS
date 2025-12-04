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

    /**
     * Obtains double signature for a transaction based on client's role.
     * Determines role (seller/buyer) from transaction JSON, then coordinates signatures:
     * - If seller: signs first, requests buyer's signature
     * - If buyer: requests seller to sign first, then signs transaction and requests buyer's signature
     * 
     * @param transactionData The transaction JSON data containing seller and buyer fields
     * @param sellerHost The hostname/IP of the seller client
     * @param sellerPort The port of the seller client
     * @param buyerHost The hostname/IP of the buyer client
     * @param buyerPort The port of the buyer client
     * @return Array with [sellerSignature, buyerSignature], or null if failed
     */
    public String[] obtainDoubleSignature(byte[] transactionData, String sellerHost, int sellerPort, String buyerHost, int buyerPort) {
        try {
            // Parse transaction data to extract the inner JSON with seller/buyer
            // Format: {request_type:transaction, ...}<json file with seller/buyer fields>
            String dataStr = new String(transactionData, java.nio.charset.StandardCharsets.UTF_8);
            
            // Find where the payload header ends
            int payloadEnd = dataStr.indexOf('}') + 1;
            if (payloadEnd <= 0) {
                System.err.println("Invalid transaction data format: missing payload header");
                return null;
            }
            
            // Extract the JSON file content (after payload, before signatures if any)
            String jsonFileStr = dataStr.substring(payloadEnd);
            
            // Find the JSON object boundaries in the file content
            int jsonEnd = jsonFileStr.indexOf('}') + 1;
            if (jsonEnd <= 0) {
                System.err.println("Invalid transaction JSON format");
                return null;
            }
            String jsonPart = jsonFileStr.substring(0, jsonEnd);
            
            // Extract seller and buyer from the inner JSON
            String seller = extractFieldValue(jsonPart, "seller");
            String buyer = extractFieldValue(jsonPart, "buyer");
            
            if (seller == null || buyer == null) {
                System.err.println("Transaction JSON missing seller or buyer field");
                return null;
            }
            
            // Determine this client's role
            boolean isSeller = this.clientName.equalsIgnoreCase(seller);
            boolean isBuyer = this.clientName.equalsIgnoreCase(buyer);
            
            if (!isSeller && !isBuyer) {
                System.err.println("This client is neither seller nor buyer in transaction");
                return null;
            }
            
            if (isSeller) {
                // This client is the seller: sign first, then request buyer's signature
                String sellerSignature = signTransactionData(transactionData);
                if (sellerSignature == null) {
                    System.err.println("Failed to create seller signature");
                    return null;
                }
                System.out.println("Seller (" + this.clientName + ") signed transaction");
                
                // Request buyer's signature
                String payload = "{request_type:signatureRequest, source: " + this.clientName + ", sellerSignature: " + sellerSignature + "}";
                byte[] payloadBytes = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] combined = new byte[payloadBytes.length + transactionData.length];
                System.arraycopy(payloadBytes, 0, combined, 0, payloadBytes.length);
                System.arraycopy(transactionData, 0, combined, payloadBytes.length, transactionData.length);
                
                byte[] responseBytes = com.chainofproduct.utils.ApiCalls.actAsSender(
                    buyerHost, buyerPort, this.entityType, this.clientNum, buyer, combined
                );
                
                if (responseBytes == null) {
                    System.err.println("Failed to get buyer signature: no response");
                    return null;
                }
                
                String response = new String(responseBytes, java.nio.charset.StandardCharsets.UTF_8);
                String buyerSignature = extractFieldValue(response, "signature");
                if (buyerSignature == null) {
                    System.err.println("Failed to get buyer signature: no signature in response");
                    return null;
                }
                
                System.out.println("Successfully obtained double signature");
                return new String[]{sellerSignature, buyerSignature};
                
            } else {
                // This client is the buyer: request seller to sign, then forward to buyer and sign
                String payload = "{request_type:signatureRequest, source: " + this.clientName + "}";
                byte[] payloadBytes = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] combined = new byte[payloadBytes.length + transactionData.length];
                System.arraycopy(payloadBytes, 0, combined, 0, payloadBytes.length);
                System.arraycopy(transactionData, 0, combined, payloadBytes.length, transactionData.length);
                
                byte[] responseBytes = com.chainofproduct.utils.ApiCalls.actAsSender(
                    sellerHost, sellerPort, this.entityType, this.clientNum, seller, combined
                );
                
                if (responseBytes == null) {
                    System.err.println("Failed to get seller signature: no response");
                    return null;
                }
                
                String response = new String(responseBytes, java.nio.charset.StandardCharsets.UTF_8);
                String sellerSignature = extractFieldValue(response, "signature");
                if (sellerSignature == null) {
                    System.err.println("Failed to get seller signature: no signature in response");
                    return null;
                }
                
                System.out.println("Received seller signature, now buyer (this client) will sign");
                
                // Now this buyer signs the transaction
                String buyerSignature = signTransactionData(transactionData);
                if (buyerSignature == null) {
                    System.err.println("Failed to create buyer signature");
                    return null;
                }
                
                System.out.println("Successfully obtained double signature");
                return new String[]{sellerSignature, buyerSignature};
            }
            
        } catch (Exception e) {
            System.err.println("Double signature error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Signs transaction data with this client's private key.
     * 
     * @param transactionData The transaction data to sign
     * @return The signature in Base64 format, or null if signing failed
     */
    private String signTransactionData(byte[] transactionData) {
        try {
            java.security.PrivateKey myPrivateKey = loadPrivateKeyFromKeystore(
                "client" + this.clientNum + "-keystore.p12",
                "client" + this.clientNum,
                "changeit"
            );
            
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] dataHash = digest.digest(transactionData);
            
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
            sig.initSign(myPrivateKey);
            sig.update(dataHash);
            byte[] signatureBytes = sig.sign();
            
            String signatureB64 = java.util.Base64.getEncoder().encodeToString(signatureBytes);
            System.out.println("Successfully signed transaction data as " + this.clientName);
            return signatureB64;
            
        } catch (Exception e) {
            System.err.println("Signing error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Handle an incoming signature request.
     * 
     * @param requestBytes The complete request bytes
     * @return Response bytes containing the signature, or null if failed
     */
    public byte[] handleSignatureRequest(byte[] requestBytes) {
        try {
            String requestStr = new String(requestBytes, java.nio.charset.StandardCharsets.UTF_8);
            
            String sourceName = extractFieldValue(requestStr, "source");
            
            if (sourceName == null) {
                System.err.println("handleSignatureRequest: Missing source");
                return null;
            }
            
            int payloadEnd = requestStr.indexOf('}') + 1;
            if (payloadEnd >= requestBytes.length) {
                System.err.println("handleSignatureRequest: No transaction data in request");
                return null;
            }
            
            byte[] transactionData = new byte[requestBytes.length - payloadEnd];
            System.arraycopy(requestBytes, payloadEnd, transactionData, 0, transactionData.length);
            
            String mySignature = signTransactionData(transactionData);
            if (mySignature == null) {
                System.err.println("handleSignatureRequest: Failed to sign transaction");
                return null;
            }
            
            String response = "{signature: " + mySignature + "}";
            return response.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
        } catch (Exception e) {
            System.err.println("Error handling signature request: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    // Helper to extract a field value from JSON-like string (handles with/without quotes)
    private String extractFieldValue(String str, String field) {
        String key = field + ":";
        int idx = str.indexOf(key);
        if (idx == -1) return null;
        int start = idx + key.length();
        int end = str.indexOf(',', start);
        if (end == -1) end = str.indexOf('}', start);
        if (end == -1) return null;
        String value = str.substring(start, end).trim();
        // Remove possible quotes or spaces
        value = value.replaceAll("[\"{}\\s]", "");
        return value;
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

    // Helper to load a public key from PKCS12 keystore (gets the public part of the key pair)
    private java.security.PublicKey loadPublicKeyFromKeystore(String keystorePath, String alias, String password) throws Exception {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            ks.load(fis, password.toCharArray());
            java.security.cert.Certificate cert = ks.getCertificate(alias);
            if (cert == null) {
                throw new java.security.KeyStoreException("No certificate found for alias: " + alias);
            }
            return cert.getPublicKey();
        }
    }

    // Helper to load a private key from PKCS12 keystore
    private java.security.PrivateKey loadPrivateKeyFromKeystore(String keystorePath, String alias, String password) throws Exception {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            ks.load(fis, password.toCharArray());
            java.security.Key key = ks.getKey(alias, password.toCharArray());
            if (key == null || !(key instanceof java.security.PrivateKey)) {
                throw new java.security.KeyStoreException("No private key found for alias: " + alias);
            }
            return (java.security.PrivateKey) key;
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
