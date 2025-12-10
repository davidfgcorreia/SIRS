package com.chainofproduct.server;

import com.chainofproduct.utils.ApiCalls;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * ServerOperations - handles all client requests in centralized architecture with full security.
 * Implements SR1-SR4 security requirements for Chain of Product.
 */
public class ServerOperations {
    private final PrivateKey serverPrivateKey;
    
    private final String dbHost;
    private final int dbPort;
    private final ObjectMapper jsonMapper;
    // In-memory cache of stored transaction IDs to provide fast duplicate detection
    private final java.util.Set<Long> storedTransactionIds = new java.util.HashSet<>();
    // For tests: last parsed transaction bytes (set on each transaction parse)
    private volatile byte[] lastParsedTransactionBytes = null;

    // Expose last parsed transaction bytes to tests
    public byte[] getLastParsedTransactionBytes() { return lastParsedTransactionBytes; }

    public ServerOperations() throws Exception {
        
        // Load server's private key for signing share operations
        String keystorePassword = getEnvOrDefault("SERVER_KEYSTORE_PASSWORD", "changeit");
        System.out.println("Loading server private key...");
        this.serverPrivateKey = loadPrivateKeyFromKeystore("server-keystore.p12", keystorePassword, "server");
        System.out.println("Server private key loaded");
        
        // Storage encryption removed: transactions are stored without at-rest encryption
        
        // Load database connection info from config using ResolveDestinations
        System.out.println("Loading database configuration...");
        String host= null ;
        int port= -1;
        try {
            com.chainofproduct.utils.ResolveDestinations.DestinationInfo dbInfo = 
            com.chainofproduct.utils.ResolveDestinations.resolve("db");
            host = dbInfo.ip;
            port = dbInfo.port;
            System.out.println("Database config loaded: " + host + ":" + port);
        } catch (Exception e) {
            System.err.println("Failed to load database info from elemets_info.json, using defaults: " + e.getMessage());
        }
        this.dbHost = host;
        this.dbPort = port;
        this.jsonMapper = new ObjectMapper();
        
        System.out.println("ServerOperations initialized successfully\n");
    }
    
    /**
     * Gets configuration value from environment variable or returns default.
     */
    private static String getEnvOrDefault(String envVar, String defaultValue) {
        String value = System.getenv(envVar);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
    
    // NOTE: storage key generation/reading removed as at-rest encryption is not used.

    /**
     * Main entry point for processing client requests.
     * @param request The decrypted request bytes from client
     * @return response bytes to send back, or null if no response needed
     */
    public byte[] processRequest(byte[] request) {
        try {
            String requestStr = new String(request, java.nio.charset.StandardCharsets.UTF_8);
            
            // Extract request type from format: {request_type: transaction, ...}
            String requestType = extractField(requestStr, "request_type");
            
            if (requestType == null) {
                return errorResponse("Invalid request format - missing request_type");
            }
            
            switch (requestType) {
                case "transaction":
                    return handleTransactionRequest(requestStr, request);
                case "share":
                    return handleShareRequest(requestStr);
                case "getById":
                    return handleGetByIdRequest(requestStr);
                case "getAll":
                    return handleGetAllRequest(requestStr);
                case "getShares":
                    return handleGetSharesRequest(requestStr);
                case "getSharesBy":
                    return handleGetSharesByRequest(requestStr);
                default:
                    return errorResponse("Unknown request type: " + requestType);
            }
        } catch (Exception e) {
            System.err.println("Error processing request: " + e.getMessage());
            e.printStackTrace();
            return errorResponse("Server error: " + e.getMessage());
        }
    }

    /**
     * Handle transaction submission from client with signature (SR3).
     * Format: {request_type: transaction, source: ClientName}[JSON_DATA]{signature:BASE64}
     * Submitter must be either seller or buyer and signs with their own key.
     */
    private byte[] handleTransactionRequest(String requestStr, byte[] fullRequest) {
        try {
            // Extract source (who's submitting)
            String source = extractField(requestStr, "source");
            if (source == null) {
                return errorResponse("Missing source field");
            }
            
            
            // Parse payload at byte-level to robustly extract transaction JSON and signatures
            byte[] reqBytes = fullRequest;
            // find end of header (first '}' character)
            int headerEnd = -1;
            for (int i = 0; i < reqBytes.length; i++) {
                if (reqBytes[i] == (byte)'}') { headerEnd = i; break; }
            }
            if (headerEnd == -1 || headerEnd + 1 >= reqBytes.length) {
                return errorResponse("Malformed request: missing JSON payload");
            }

            int cursor = headerEnd + 1; // start of transaction JSON (should be '{')
            // Skip any whitespace
            while (cursor < reqBytes.length && Character.isWhitespace(reqBytes[cursor])) cursor++;
            if (cursor >= reqBytes.length || reqBytes[cursor] != (byte)'{') {
                return errorResponse("Malformed request: transaction JSON not found");
            }

            // Find matching closing brace for the transaction JSON by counting braces
            int braceCount = 0;
            int txStart = cursor;
            int txEnd = -1;
            for (int i = txStart; i < reqBytes.length; i++) {
                if (reqBytes[i] == (byte)'{') braceCount++;
                else if (reqBytes[i] == (byte)'}') braceCount--;
                if (braceCount == 0) { txEnd = i; break; }
            }
            if (txEnd == -1) return errorResponse("Malformed transaction JSON: unmatched braces");

            byte[] transactionBytes = java.util.Arrays.copyOfRange(reqBytes, txStart, txEnd + 1);
            // store parsed bytes for test-time verification
            this.lastParsedTransactionBytes = java.util.Arrays.copyOf(transactionBytes, transactionBytes.length);
            String transactionJson = new String(transactionBytes, java.nio.charset.StandardCharsets.UTF_8);

            // Collect all signature occurrences after transaction JSON
            java.util.List<String> signatures = new ArrayList<>();
            int idx = txEnd + 1;
            while (idx < reqBytes.length) {
                // skip whitespace
                while (idx < reqBytes.length && Character.isWhitespace(reqBytes[idx])) idx++;
                if (idx >= reqBytes.length) break;
                if (reqBytes[idx] != (byte)'{') break; // no more brace blocks
                // find end of this small object (assume single-level)
                int j = idx;
                while (j < reqBytes.length && reqBytes[j] != (byte)'}') j++;
                if (j >= reqBytes.length) break;
                String block = new String(reqBytes, idx, j - idx + 1, java.nio.charset.StandardCharsets.UTF_8);
                String sig = extractField(block, "signature");
                if (sig != null) signatures.add(sig);
                idx = j + 1;
            }

            if (signatures.isEmpty()) {
                return errorResponse("Missing signature");
            }
            
            // Parse transaction fields
            long id = extractLongField(transactionJson, "id");
            long timestamp = extractLongField(transactionJson, "timestamp");
            String seller = extractField(transactionJson, "seller");
            String buyer = extractField(transactionJson, "buyer");
            String product = extractField(transactionJson, "product");
            long units = extractLongField(transactionJson, "units");
            long amount = extractLongField(transactionJson, "amount");
            
            
            
            if (seller == null || buyer == null || product == null) {
                return errorResponse("Missing required transaction fields");
            }
            
            // SR2: Only seller or buyer can submit transaction
            if (!source.equals(seller) && !source.equals(buyer)) {
                return errorResponse("Access denied: only seller or buyer can submit transaction");
            }
            
            // Check for duplicate transaction id: if already exists, reject to prevent replay
            // Fast in-memory check first
            if (storedTransactionIds.contains(id)) {
                return errorResponse("Transaction already exists: id=" + id);
            }

            // Fallback: check database if available
            ObjectNode checkRequest = jsonMapper.createObjectNode();
            checkRequest.put("sql", 5);
            checkRequest.put("id", id);
            byte[] existing = sendDatabaseRequest(checkRequest);
            if (existing != null) {
                try {
                    JsonNode existingNode = jsonMapper.readTree(existing);
                    boolean looksLikeTx = existingNode.has("id") || existingNode.has("seller") || existingNode.has("buyer");
                    if (looksLikeTx) {
                        return errorResponse("Transaction already exists: id=" + id);
                    }
                } catch (Exception _e) {
                    // If payload isn't JSON or parse fails, continue
                }
            }
            
            

            // SR3: Verify signatures found in payload against seller and buyer public keys
            PublicKey sellerPubKey = getCompanyPublicKey(seller);
            PublicKey buyerPubKey = getCompanyPublicKey(buyer);

            String sellerSig = "";
            String buyerSig = "";
            for (String sigB64 : signatures) {
                try {
                    boolean okSeller = false;
                    try { okSeller = verifySignature(transactionBytes, sigB64, sellerPubKey); } catch (Exception _e) { okSeller = false; }
                    
                    if (sellerSig.isEmpty() && okSeller) {
                        sellerSig = sigB64;
                    }
                } catch (Exception e) {
                    // ignore and continue
                }
                try {
                    boolean okBuyer = false;
                    try { okBuyer = verifySignature(transactionBytes, sigB64, buyerPubKey); } catch (Exception _e) { okBuyer = false; }
                    
                    if (buyerSig.isEmpty() && okBuyer) {
                        buyerSig = sigB64;
                    }
                } catch (Exception e) {
                    // ignore and continue
                }
            }

            boolean sourceVerified = (source.equals(seller) && !sellerSig.isEmpty()) || (source.equals(buyer) && !buyerSig.isEmpty());
            if (!sourceVerified) {
                return errorResponse("Invalid signature from " + source);
            }

            System.out.println("Storing transaction: id=" + id + ", seller=" + seller + ", buyer=" + buyer + ", submitted by=" + source + ", sellerSigPresent=" + (!sellerSig.isEmpty()) + ", buyerSigPresent=" + (!buyerSig.isEmpty()));
            
            // Transactions are stored without at-rest encryption
            // Store in database with signature via TCP (sql=0: insertTransaction)
            ObjectNode dbRequest = jsonMapper.createObjectNode();
            dbRequest.put("sql", 0);
            dbRequest.put("id", id);
            dbRequest.put("timestamp", timestamp);
            dbRequest.put("seller", seller);
            dbRequest.put("buyer", buyer);
            dbRequest.put("product", product);
            dbRequest.put("units", units);
            dbRequest.put("amount", amount);
            dbRequest.put("sellerSignature", sellerSig);
            dbRequest.put("buyerSignature", buyerSig);
            dbRequest.put("data", transactionJson);
            sendDatabaseRequest(dbRequest);
            // Mark transaction as stored in in-memory cache immediately after DB insert (tests rely on quick in-memory replay protection)
            storedTransactionIds.add(id);
            
            long shareTime = System.currentTimeMillis();
            String shareData = String.format("%d:%s:server", id, seller);
            String sellerShareSig = signData(shareData.getBytes(), serverPrivateKey);
            
            ObjectNode shareRequest1 = jsonMapper.createObjectNode();
            shareRequest1.put("sql", 1);
            shareRequest1.put("transactionId", id);
            shareRequest1.put("share", seller);
            shareRequest1.put("sharedBy", "server");
            shareRequest1.put("timestamp", shareTime);
            shareRequest1.put("signature", sellerShareSig);
            sendDatabaseRequest(shareRequest1);

            shareData = String.format("%d:%s:server", id, buyer);
            String buyerShareSig = signData(shareData.getBytes(), serverPrivateKey);

            ObjectNode shareRequest2 = jsonMapper.createObjectNode();
            shareRequest2.put("sql", 1);
            shareRequest2.put("transactionId", id);
            shareRequest2.put("share", buyer);
            shareRequest2.put("sharedBy", "server");
            shareRequest2.put("timestamp", shareTime);
            shareRequest2.put("signature", buyerShareSig);
            sendDatabaseRequest(shareRequest2);
            
            return successResponse("Transaction stored successfully with id=" + id + ", signed by " + source);
            
        } catch (Exception e) {
            e.printStackTrace();
            return errorResponse("Transaction processing error: " + e.getMessage());
        }
    }
    
    /**
     * Handle share transaction with another party (SR2, SR4).
     * Format: {request_type:share, source:CompanyName, transaction_id:123, share_with:OtherCompany}{signature:BASE64}
     */
    private byte[] handleShareRequest(String requestStr) {
        try {
            String source = extractField(requestStr, "source");
            long id = extractLongField(requestStr, "transaction_id");
            String shareWith = extractField(requestStr, "share_with");
            String signature = extractField(requestStr, "signature");
            
            if (source == null || shareWith == null || signature == null) {
                return errorResponse("Missing required share parameters");
            }
            
            // Get transaction to verify access via TCP (sql=5: getTransactionById)
            ObjectNode getRequest = jsonMapper.createObjectNode();
            getRequest.put("sql", 5);
            getRequest.put("id", id);
            byte[] recBytes = sendDatabaseRequest(getRequest);
            if (recBytes == null) {
                return errorResponse("Transaction not found");
            }
            JsonNode recNode = jsonMapper.readTree(recBytes);
            String recSeller = recNode.get("seller").asText();
            String recBuyer = recNode.get("buyer").asText();
            
            // SR2: Only seller or buyer can share
            if (!source.equals(recSeller) && !source.equals(recBuyer)) {
                return errorResponse("Access denied: only seller or buyer can share this transaction");
            }
            
            // Verify signature on share request
            String shareData = String.format("%d:%s:%s", id, shareWith, source);
            PublicKey sourcePubKey = getCompanyPublicKey(source);
            if (!verifySignature(shareData.getBytes(), signature, sourcePubKey)) {
                return errorResponse("Invalid share signature");
            }
            
            // SR4: Add share with cryptographic proof via TCP (sql=1: addShare)
            long shareTime = System.currentTimeMillis();
            ObjectNode shareRequest = jsonMapper.createObjectNode();
            shareRequest.put("sql", 1);
            shareRequest.put("transactionId", id);
            shareRequest.put("share", shareWith);
            shareRequest.put("sharedBy", source);
            shareRequest.put("timestamp", shareTime);
            shareRequest.put("signature", signature);
            sendDatabaseRequest(shareRequest);
            
            return successResponse("Transaction shared with " + shareWith);
            
        } catch (Exception e) {
            e.printStackTrace();
            return errorResponse("Share error: " + e.getMessage());
        }
    }

    /**
     * Handle get transaction by ID request with access control (SR1).
     * Format: {request_type:getById, source: ClientName, transaction_id: 123}
     */
    private byte[] handleGetByIdRequest(String requestStr) {
        try {
            String source = extractField(requestStr, "source");
            if (source == null) source = extractField(requestStr, "servername"); // fallback
            
            long id = extractLongField(requestStr, "transaction_id");
            
            // Get transaction via TCP (sql=5: getTransactionById)
            ObjectNode getRequest = jsonMapper.createObjectNode();
            getRequest.put("sql", 5);
            getRequest.put("id", id);
            byte[] recBytes = sendDatabaseRequest(getRequest);
            if (recBytes == null) {
                return errorResponse("Transaction not found: " + id);
            }
            JsonNode rec = jsonMapper.readTree(recBytes);
            
            // SR1: Check if requester has access via TCP (sql=2: getShares)
            ObjectNode sharesRequest = jsonMapper.createObjectNode();
            sharesRequest.put("sql", 2);
            sharesRequest.put("transactionId", id);
            byte[] sharesBytes = sendDatabaseRequest(sharesRequest);
            JsonNode sharesNode = jsonMapper.readTree(sharesBytes);
            List<String> shares = new ArrayList<>();
            if (sharesNode.isArray()) {
                for (JsonNode node : sharesNode) {
                    shares.add(node.asText());
                }
            }
            if (!shares.contains(source)) {
                return errorResponse("Access denied: transaction not shared with you");
            }
            
            // Return transaction with signatures for verification (SR3)
            String json = String.format(
                "{\"id\":%d,\"timestamp\":%d,\"seller\":\"%s\",\"buyer\":\"%s\",\"product\":\"%s\",\"units\":%d,\"amount\":%d,\"seller_signature\":\"%s\",\"buyer_signature\":\"%s\"}",
                rec.get("id").asLong(), rec.get("timestamp").asLong(), rec.get("seller").asText(), 
                rec.get("buyer").asText(), rec.get("product").asText(), rec.get("units").asLong(), 
                rec.get("amount").asLong(), rec.get("sellerSignature").asText(), rec.get("buyerSignature").asText()
            );
            
            return json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return errorResponse("Get by ID error: " + e.getMessage());
        }
    }

    /**
     * Handle get all transactions request with access control (SR1).
     * Uses batch query to avoid N+1 problem.
     * Format: {request_type:getAll, source: ClientName}
     */
    private byte[] handleGetAllRequest(String requestStr) {
        try {
            String source = extractField(requestStr, "source");
            if (source == null) source = extractField(requestStr, "servername"); // fallback
            
            // Get all transactions with shares in single batch query (sql=11: getAllTransactionsWithShares)
            ObjectNode getAllRequest = jsonMapper.createObjectNode();
            getAllRequest.put("sql", 11);
            getAllRequest.put("requester", source);
            byte[] allBytes = sendDatabaseRequest(getAllRequest);
            JsonNode allRecords = jsonMapper.readTree(allBytes);
            
            StringBuilder json = new StringBuilder("{\"transactions\":[");
            boolean first = true;
            
            if (allRecords.isArray()) {
                for (JsonNode rec : allRecords) {
                    if (!first) json.append(",");
                    first = false;
                    json.append(String.format(
                        "{\"id\":%d,\"timestamp\":%d,\"seller\":\"%s\",\"buyer\":\"%s\",\"product\":\"%s\",\"units\":%d,\"amount\":%d,\"seller_signature\":\"%s\",\"buyer_signature\":\"%s\"}",
                        rec.get("id").asLong(), rec.get("timestamp").asLong(), rec.get("seller").asText(),
                        rec.get("buyer").asText(), rec.get("product").asText(), rec.get("units").asLong(),
                        rec.get("amount").asLong(), rec.get("sellerSignature").asText(), rec.get("buyerSignature").asText()
                    ));
                }
            }
            json.append("]}");
            
            return json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
        } catch (Exception e) {
            return errorResponse("Get all error: " + e.getMessage());
        }
    }

    /**
     * Handle get shares for transaction request with cryptographic proofs (SR4).
     * Format: {request_type:getShares, source: ClientName, transaction_id: 123}
     */
    private byte[] handleGetSharesRequest(String requestStr) {
        try {
            long id = extractLongField(requestStr, "transaction_id");
            String source = extractField(requestStr, "source");
            if (source == null) source = extractField(requestStr, "servername"); // fallback
            
            // SR1: Check access via TCP
            ObjectNode getRequest = jsonMapper.createObjectNode();
            getRequest.put("sql", 5);
            getRequest.put("id", id);
            byte[] recBytes = sendDatabaseRequest(getRequest);
            if (recBytes == null) {
                return errorResponse("Transaction not found");
            }
            
            ObjectNode sharesRequest = jsonMapper.createObjectNode();
            sharesRequest.put("sql", 2);
            sharesRequest.put("transactionId", id);
            byte[] sharesBytes = sendDatabaseRequest(sharesRequest);
            JsonNode sharesNode = jsonMapper.readTree(sharesBytes);
            List<String> shares = new ArrayList<>();
            if (sharesNode.isArray()) {
                for (JsonNode node : sharesNode) {
                    shares.add(node.asText());
                }
            }
            if (!shares.contains(source)) {
                return errorResponse("Access denied: transaction not shared with you");
            }
            
            // SR4: Get share records with cryptographic proof (sql=9: getShareRecords)
            ObjectNode shareRecordsRequest = jsonMapper.createObjectNode();
            shareRecordsRequest.put("sql", 9);
            shareRecordsRequest.put("transactionId", id);
            byte[] shareRecordsBytes = sendDatabaseRequest(shareRecordsRequest);
            JsonNode shareRecords = jsonMapper.readTree(shareRecordsBytes);
            
            StringBuilder json = new StringBuilder("{\"shares\":[");
            if (shareRecords.isArray()) {
                for (int i = 0; i < shareRecords.size(); i++) {
                    if (i > 0) json.append(",");
                    JsonNode record = shareRecords.get(i);
                    json.append(String.format(
                        "{\"company\":\"%s\",\"shared_by\":\"%s\",\"timestamp\":%d,\"signature\":\"%s\"}",
                        record.get("share").asText(),
                        record.get("sharedBy").asText(),
                        record.get("timestamp").asLong(),
                        record.get("signature").asText()
                    ));
                }
            }
            json.append("]}");
            
            return json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
        } catch (Exception e) {
            return errorResponse("Get shares error: " + e.getMessage());
        }
    }

    /**
     * Handle get shares by sharedBy request with cryptographic proofs (SR4).
     * Format: {request_type:getSharesBy, source: ClientName, transaction_id: 123, shared_by: CompanyName}
     */
    private byte[] handleGetSharesByRequest(String requestStr) {
        try {
            long id = extractLongField(requestStr, "transaction_id");
            String sharedBy = extractField(requestStr, "shared_by");
            String source = extractField(requestStr, "source");
            if (source == null) source = extractField(requestStr, "servername"); // fallback
            
            if (sharedBy == null) {
                return errorResponse("Missing shared_by parameter");
            }
            
            // SR1: Check access via TCP (sql=2: getShares)
            ObjectNode sharesRequest = jsonMapper.createObjectNode();
            sharesRequest.put("sql", 2);
            sharesRequest.put("transactionId", id);
            byte[] sharesBytes = sendDatabaseRequest(sharesRequest);
            JsonNode sharesNode = jsonMapper.readTree(sharesBytes);
            List<String> shares = new ArrayList<>();
            if (sharesNode.isArray()) {
                for (JsonNode node : sharesNode) {
                    shares.add(node.asText());
                }
            }
            if (!shares.contains(source)) {
                return errorResponse("Access denied: transaction not shared with you");
            }
            
            // SR4: Get shares by sharedBy with timestamp and signature (sql=10: getShareRecordsBySharedBy)
            ObjectNode getByRequest = jsonMapper.createObjectNode();
            getByRequest.put("sql", 10);
            getByRequest.put("transactionId", id);
            getByRequest.put("sharedBy", sharedBy);
            byte[] sharesByBytes = sendDatabaseRequest(getByRequest);
            JsonNode shareRecords = jsonMapper.readTree(sharesByBytes);
            
            StringBuilder json = new StringBuilder("{\"shares\":[");
            if (shareRecords.isArray()) {
                for (int i = 0; i < shareRecords.size(); i++) {
                    if (i > 0) json.append(",");
                    JsonNode record = shareRecords.get(i);
                    json.append(String.format(
                        "{\"company\":\"%s\",\"shared_by\":\"%s\",\"timestamp\":%d,\"signature\":\"%s\"}",
                        record.get("share").asText(),
                        record.get("sharedBy").asText(),
                        record.get("timestamp").asLong(),
                        record.get("signature").asText()
                    ));
                }
            }
            json.append("]}");
            
            return json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
        } catch (Exception e) {
            return errorResponse("Get shares by error: " + e.getMessage());
        }
    }
    
    /**
     * Helper: Load private key from PKCS12 keystore.
     */
    public PrivateKey loadPrivateKeyFromKeystore(String keystorePath, String password, String alias) throws Exception {
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
            keyStore.load(fis, password.toCharArray());
        }
        return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    }
    
    /**
     * Helper: Load public key from PKCS12 truststore.
     */
    public PublicKey loadPublicKeyFromKeystore(String truststorePath, String password, String alias) throws Exception {
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(truststorePath)) {
            keyStore.load(fis, password.toCharArray());
        }
        java.security.cert.Certificate cert = keyStore.getCertificate(alias);
        if (cert == null) {
            throw new Exception("Certificate not found for alias: " + alias);
        }
        return cert.getPublicKey();
    }
    
    /**
     * Helper: Sign data using RSA private key.
     */
    private String signData(byte[] data, PrivateKey privateKey) throws Exception {
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        byte[] signature = sig.sign();
        return Base64.getEncoder().encodeToString(signature);
    }
    
    /**
     * Helper: Verify RSA signature.
     */
    private boolean verifySignature(byte[] data, String signatureB64, PublicKey publicKey) throws Exception {
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        byte[] signature = Base64.getDecoder().decode(signatureB64);
        return sig.verify(signature);
    }
    
    /**
     * Helper: Load public key for a company from truststore.
     * Maps company names to certificate aliases.
     */
    private PublicKey getCompanyPublicKey(String companyName) throws Exception {
        // Try multiple alias formats to find the certificate
        String[] possibleAliases = {
            companyName,  // Original name (e.g., "TestCompany")
            companyName.toLowerCase(),  // Lowercase (e.g., "testcompany")
            companyName.toLowerCase().replace(" ", "").replace("-", ""),  // Cleaned (e.g., "testcompany")
        };
        
        // Try to load from server's truststore with different alias formats
        for (String alias : possibleAliases) {
            try {
                return loadPublicKeyFromKeystore("server-truststore.p12", "changeit", alias);
            } catch (Exception e) {
                // Try next alias format
            }
        }
        
        // If all formats fail, throw exception with helpful message
        throw new Exception("Certificate not found for company: " + companyName + 
            ". Tried aliases: " + String.join(", ", possibleAliases));
    }
    
    /**
     * Helper: Send JSON request to database server over TCP and get response.
     */
    private byte[] sendDatabaseRequest(ObjectNode request) throws Exception {
        byte[] requestBytes = jsonMapper.writeValueAsBytes(request);
        try {
            byte[] resp = ApiCalls.actAsSender(dbHost, dbPort, "server", 0, "db", requestBytes);
            if (resp == null) {
                System.out.println("DEBUG: sendDatabaseRequest response=null for sql=" + request.get("sql"));
            } else {
                System.out.println("DEBUG: sendDatabaseRequest response=" + new String(resp, java.nio.charset.StandardCharsets.UTF_8) + " for sql=" + request.get("sql"));
            }
            return resp;
        } catch (Throwable t) {
            System.out.println("DEBUG: sendDatabaseRequest threw: " + t.getMessage());
            throw t;
        }
    }

    // Helper methods for simple string parsing
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

    private long extractLongField(String str, String fieldName) {
        String value = extractField(str, fieldName);
        if (value == null) return 0;
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private byte[] errorResponse(String message) {
        String json = "{\"error\":\"" + message.replace("\"", "\\\"") + "\"}";
        return json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private byte[] successResponse(String message) {
        String json = "{\"success\":true,\"message\":\"" + message.replace("\"", "\\\"") + "\"}";
        return json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
}