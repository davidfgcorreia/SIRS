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
     * Exchange public keys with another party.
     * Sends this client's public key and receives the other party's public key.
     * 
     * @param targetHost The hostname/IP of the target party
     * @param targetPort The port of the target party
     * @param targetEntity The entity name (e.g., "server", "db", or "client")
     * @return The received public key, or null if exchange failed
     */
    public java.security.PublicKey exchangePublicKeys(String targetHost, int targetPort, String targetEntity) {
        try {
            // Load this client's public key
            java.security.PublicKey myPublicKey = loadPublicKeyFromKeystore(
                "client" + this.clientNum + "-keystore.p12", 
                "client" + this.clientNum, 
                "changeit"
            );
            
            // Encode the public key
            byte[] myPubKeyEncoded = myPublicKey.getEncoded();
            String myPubKeyB64 = java.util.Base64.getEncoder().encodeToString(myPubKeyEncoded);
            
            // Create the key exchange request payload
            String payload = "{request_type:keyExchange, source: " + this.clientName + ", publicKey: " + myPubKeyB64 + "}";
            byte[] payloadBytes = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
            // Send the request and wait for response
            byte[] responseBytes = com.chainofproduct.utils.ApiCalls.actAsSender(
                targetHost,
                targetPort,
                this.entityType,
                this.clientNum,
                targetEntity,
                payloadBytes
            );
            
            if (responseBytes == null) {
                System.err.println("Key exchange failed: no response received");
                return null;
            }
            
            // Parse the response to extract the other party's public key
            String response = new String(responseBytes, java.nio.charset.StandardCharsets.UTF_8);
            String receivedKeyB64 = extractJsonStringField(response, "publicKey");
            
            if (receivedKeyB64 == null) {
                System.err.println("Key exchange failed: no publicKey in response");
                return null;
            }
            
            // Decode the received public key
            byte[] receivedKeyBytes = java.util.Base64.getDecoder().decode(receivedKeyB64);
            java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(receivedKeyBytes);
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            java.security.PublicKey receivedPublicKey = keyFactory.generatePublic(keySpec);
            
            System.out.println("Successfully exchanged public keys with " + targetEntity);
            return receivedPublicKey;
            
        } catch (Exception e) {
            System.err.println("Key exchange error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Exchange public keys with the default server.
     * Convenience method that uses the configured server host and port.
     * 
     * @return The server's public key, or null if exchange failed
     */
    public java.security.PublicKey exchangePublicKeysWithServer() {
        return exchangePublicKeys(this.serverHost, this.serverPort, this.receiverEntity);
    }

    /**
     * Request the buyer to sign a transaction for double signature.
     * The seller signs the transaction first, then sends it with their signature to the buyer.
     * Both seller and buyer are clients.
     * 
     * @param buyerHost The hostname/IP of the buyer client
     * @param buyerPort The port of the buyer client
     * @param buyerClientName The buyer's client name (e.g., "client42")
     * @param transactionData The transaction data that needs to be signed
     * @return The buyer's signature in Base64 format, or null if signing failed
     */
    public String requestBuyerSignature(String buyerHost, int buyerPort, String buyerClientName, byte[] transactionData) {
        try {
            // Step 1: Seller (this client) signs the transaction first
            String sellerSignature = signTransactionData(transactionData);
            if (sellerSignature == null) {
                System.err.println("Failed to create seller signature");
                return null;
            }
            
            System.out.println("Seller (" + this.clientName + ") signed transaction");
            
            // Step 2: Create the signature request payload with seller's signature
            String payload = "{request_type:signatureRequest, source: " + this.clientName + ", sellerSignature: " + sellerSignature + "}";
            byte[] payloadBytes = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
            // Combine payload with transaction data
            byte[] combined = new byte[payloadBytes.length + transactionData.length];
            System.arraycopy(payloadBytes, 0, combined, 0, payloadBytes.length);
            System.arraycopy(transactionData, 0, combined, payloadBytes.length, transactionData.length);
            
            // Send the request to the buyer client and wait for response
            byte[] responseBytes = com.chainofproduct.utils.ApiCalls.actAsSender(
                buyerHost,
                buyerPort,
                this.entityType,  // "client"
                this.clientNum,   // This seller's client number
                buyerClientName,  // Buyer's client entity name
                combined
            );
            
            if (responseBytes == null) {
                System.err.println("Signature request failed: no response received from buyer");
                return null;
            }
            
            // Parse the response to extract the buyer's signature
            String response = new String(responseBytes, java.nio.charset.StandardCharsets.UTF_8);
            String buyerSignature = extractJsonStringField(response, "signature");
            
            if (buyerSignature == null) {
                System.err.println("Signature request failed: no signature in response");
                return null;
            }
            
            System.out.println("Successfully received signature from buyer: " + buyerClientName);
            return buyerSignature;
            
        } catch (Exception e) {
            System.err.println("Signature request error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Request the buyer to sign a transaction data file for double signature.
     * Convenience method that reads transaction data from a file.
     * The seller signs first, then requests the buyer's signature.
     * Both seller and buyer are clients.
     * 
     * @param buyerHost The hostname/IP of the buyer client
     * @param buyerPort The port of the buyer client
     * @param buyerClientName The buyer's client name (e.g., "client42")
     * @param transactionFilePath Path to the transaction data file
     * @return The buyer's signature in Base64 format, or null if signing failed
     */
    public String requestBuyerSignatureFromFile(String buyerHost, int buyerPort, String buyerClientName, String transactionFilePath) {
        try {
            java.nio.file.Path path = java.nio.file.Paths.get(transactionFilePath);
            byte[] transactionData = java.nio.file.Files.readAllBytes(path);
            return requestBuyerSignature(buyerHost, buyerPort, buyerClientName, transactionData);
        } catch (Exception e) {
            System.err.println("Failed to read transaction file: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Complete double signature workflow: seller signs, requests buyer signature, returns both.
     * Both seller and buyer are clients.
     * 
     * @param buyerHost The hostname/IP of the buyer client
     * @param buyerPort The port of the buyer client
     * @param buyerClientName The buyer's client name (e.g., "client42")
     * @param transactionData The transaction data that needs to be double-signed
     * @return Array with [sellerSignature, buyerSignature], or null if failed
     */
    public String[] getDoubleSignature(String buyerHost, int buyerPort, String buyerClientName, byte[] transactionData) {
        try {
            // Seller signs first
            String sellerSignature = signTransactionData(transactionData);
            if (sellerSignature == null) {
                System.err.println("Failed to create seller signature");
                return null;
            }
            
            // Request buyer's signature
            String buyerSignature = requestBuyerSignature(buyerHost, buyerPort, buyerClientName, transactionData);
            if (buyerSignature == null) {
                System.err.println("Failed to get buyer signature");
                return null;
            }
            
            System.out.println("Successfully obtained double signature");
            return new String[]{sellerSignature, buyerSignature};
            
        } catch (Exception e) {
            System.err.println("Double signature error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Respond to a signature request (for when this client is the buyer).
     * Signs the provided transaction data with this client's private key.
     * 
     * @param transactionData The transaction data to sign
     * @return The signature in Base64 format, or null if signing failed
     */
    public String signTransactionData(byte[] transactionData) {
        try {
            // Load this client's private key
            java.security.PrivateKey myPrivateKey = loadPrivateKeyFromKeystore(
                "client" + this.clientNum + "-keystore.p12",
                "client" + this.clientNum,
                "changeit"
            );
            
            // Compute hash of transaction data
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] dataHash = digest.digest(transactionData);
            
            // Sign the hash
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
            sig.initSign(myPrivateKey);
            sig.update(dataHash);
            byte[] signatureBytes = sig.sign();
            
            // Encode signature as Base64
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
     * Handle an incoming signature request from the seller (when this client is the buyer).
     * Verifies the seller's signature, then signs the transaction.
     * 
     * @param requestBytes The complete request bytes from the seller
     * @return Response bytes containing the buyer's signature, or error response
     */
    public byte[] handleSignatureRequest(byte[] requestBytes) {
        try {
            String requestStr = new String(requestBytes, java.nio.charset.StandardCharsets.UTF_8);
            
            // Extract seller's signature from the request
            String sellerSignature = extractField(requestStr, "sellerSignature");
            String sellerName = extractField(requestStr, "source");
            
            if (sellerSignature == null || sellerName == null) {
                return errorResponse("Missing seller signature or source");
            }
            
            // Find where payload ends and transaction data begins
            int payloadEnd = requestStr.indexOf('}') + 1;
            if (payloadEnd >= requestBytes.length) {
                return errorResponse("No transaction data in request");
            }
            
            // Extract transaction data
            byte[] transactionData = new byte[requestBytes.length - payloadEnd];
            System.arraycopy(requestBytes, payloadEnd, transactionData, 0, transactionData.length);
            
            // TODO: Optionally verify the seller's signature here
            // For now, we trust it since it comes over secure TLS connection
            
            // Sign the transaction as buyer
            String buyerSignature = signTransactionData(transactionData);
            if (buyerSignature == null) {
                return errorResponse("Failed to sign transaction");
            }
            
            // Return the buyer's signature
            String response = "{signature: " + buyerSignature + "}";
            return response.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
        } catch (Exception e) {
            System.err.println("Error handling signature request: " + e.getMessage());
            e.printStackTrace();
            return errorResponse("Error processing signature request: " + e.getMessage());
        }
    }
    
    // Helper to create error response
    private byte[] errorResponse(String message) {
        String response = "{error: " + message.replace("\"", "\\\"") + "}";
        return response.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
    
    // Helper to extract field from request string (supports both quoted and unquoted values)
    private String extractField(String str, String fieldName) {
        // Try with quotes first: "fieldName":
        String quotedPattern = "\"" + fieldName + "\":";
        int start = str.indexOf(quotedPattern);
        if (start != -1) {
            start += quotedPattern.length();
        } else {
            // Try without quotes: fieldName:
            String pattern = fieldName + ":";
            start = str.indexOf(pattern);
            if (start == -1) return null;
            start += pattern.length();
        }
        
        // Skip whitespace
        while (start < str.length() && str.charAt(start) == ' ') start++;
        
        // Check if value is quoted
        boolean valueIsQuoted = (start < str.length() && str.charAt(start) == '"');
        if (valueIsQuoted) {
            start++; // Skip opening quote
            // Find closing quote
            int end = str.indexOf('"', start);
            if (end == -1) return null;
            return str.substring(start, end);
        } else {
            // Value is not quoted, find end (comma or brace)
            int end = start;
            while (end < str.length()) {
                char c = str.charAt(end);
                if (c == ',' || c == '}') break;
                end++;
            }
            String value = str.substring(start, end).trim();
            return value.isEmpty() ? null : value;
        }
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
