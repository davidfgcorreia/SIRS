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

public class ServerOperations {
    
    private final String dbHost;
    private final int dbPort;
    private final ObjectMapper jsonMapper;
    // In-memory cache of stored transaction IDs to provide fast duplicate detection
    private volatile byte[] lastParsedTransactionBytes = null;

    // Expose last parsed transaction bytes to tests
    public byte[] getLastParsedTransactionBytes() { return lastParsedTransactionBytes; }

    public ServerOperations() throws Exception {

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
     * Main entry point for processing client requests.
     * @param request The decrypted request bytes from client
     * @return response bytes to send back, or null if no response needed
     */
    public byte[] processRequest(byte[] request, String clientName) {
        try {
            String requestStr = new String(request, java.nio.charset.StandardCharsets.UTF_8);
            
            // Extract request type from format: {request_type: transaction, ...}
            String requestType = extractField(requestStr, "request_type");
            
            if (requestType == null) {
                return errorResponse("Invalid request format - missing request_type");
            }
            
            switch (requestType) {
                case "transaction":
                    return handleTransactionRequest(requestStr, request, clientName);
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

    private byte[] handleTransactionRequest(String requestStr, byte[] fullRequest, String clientName) {
        // The payload is: header JSON, transaction JSON, 344-byte signature1, 344-byte signature2 (all concatenated in binary)
        // We'll parse the first two JSONs, then extract the two signatures by length

        int sigLen = 344; // bytes
        if (fullRequest.length < sigLen * 2 + 2) {
            return errorResponse("Malformed transaction payload: too short for two signatures");
        }

        // Find the end of the first JSON (header)
        int headerEnd = -1;
        int braceCount = 0;
        for (int i = 0; i < fullRequest.length; i++) {
            if (fullRequest[i] == '{') braceCount++;
            if (fullRequest[i] == '}') braceCount--;
            if (braceCount == 0) {
                headerEnd = i + 1;
                break;
            }
        }
        if (headerEnd == -1) return errorResponse("Malformed transaction payload: could not find end of header JSON");

        // Find the end of the second JSON (transaction)
        int txnStart = headerEnd;
        int txnEnd = -1;
        braceCount = 0;
        for (int i = txnStart; i < fullRequest.length; i++) {
            if (fullRequest[i] == '{') braceCount++;
            if (fullRequest[i] == '}') braceCount--;
            if (braceCount == 0) {
                txnEnd = i + 1;
                break;
            }
        }
        if (txnEnd == -1) return errorResponse("Malformed transaction payload: could not find end of transaction JSON");

        // Parse header JSON
        JsonNode header;
        try {
            header = jsonMapper.readTree(new String(fullRequest, 0, headerEnd, java.nio.charset.StandardCharsets.UTF_8));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            return errorResponse("Invalid header JSON: " + e.getMessage());
        }

        // Parse transaction JSON
        JsonNode transaction;
        try {
            transaction = jsonMapper.readTree(new String(fullRequest, txnStart, txnEnd - txnStart, java.nio.charset.StandardCharsets.UTF_8));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            return errorResponse("Invalid transaction JSON: " + e.getMessage());
        }

        // Extract signatures
        int sig1Start = txnEnd;
        int sig2Start = sig1Start + sigLen;
        if (fullRequest.length < sig2Start + sigLen) {
            return errorResponse("Malformed transaction payload: not enough data for two signatures");
        }
        String signature1 = new String(fullRequest, sig1Start, sigLen, java.nio.charset.StandardCharsets.UTF_8).trim();
        String signature2 = new String(fullRequest, sig2Start, sigLen, java.nio.charset.StandardCharsets.UTF_8).trim();

        // Validate header fields
        String[] headerFields = {"request_type", "source", "destination", "role", "group"};
        for (String field : headerFields) {
            if (!header.has(field)) {
            return errorResponse("Header missing required field: " + field);
            }
        }
        // Extract header fields
        String source = header.get("source").asText();
        String destination = header.get("destination").asText();

        // Validate transaction fields (example: id, timestamp, seller, buyer, product, units, amount)
        String[] txnFields = {"id", "timestamp", "seller", "buyer", "product", "units", "amount"};
        for (String field : txnFields) {
            if (!transaction.has(field)) {
                return errorResponse("Transaction missing required field: " + field);
            }
        }
        // Extract transaction fields
        long id = transaction.get("id").asLong();
        String seller = transaction.get("seller").asText();
        String buyer = transaction.get("buyer").asText();


        // Validate signatures are present
        if (signature1.isEmpty() || signature2.isEmpty()) {
            return errorResponse("Missing one or both signatures");
        }


        // Concatenate: Request JSON + original folowing bytes to the header on the full request


        // --- Build DB payload: header JSON + original transaction JSON + signatures ---
        int headerLen = headerEnd;
        int transactionJsonLen = txnEnd - txnStart;
        byte[] headerBytes = new byte[headerLen];
        System.arraycopy(fullRequest, 0, headerBytes, 0, headerLen);
        byte[] transactionBytes = new byte[transactionJsonLen];
        System.arraycopy(fullRequest, txnStart, transactionBytes, 0, transactionJsonLen);
        byte[] signature1Bytes = new byte[sigLen];
        System.arraycopy(fullRequest, sig1Start, signature1Bytes, 0, sigLen);
        byte[] signature2Bytes = new byte[sigLen];
        System.arraycopy(fullRequest, sig2Start, signature2Bytes, 0, sigLen);

        int totalLen = headerBytes.length + transactionBytes.length + signature1Bytes.length + signature2Bytes.length;
        byte[] dbPayload = new byte[totalLen];
        int pos = 0;
        System.arraycopy(headerBytes, 0, dbPayload, pos, headerBytes.length);
        pos += headerBytes.length;
        System.arraycopy(transactionBytes, 0, dbPayload, pos, transactionBytes.length);
        pos += transactionBytes.length;
        System.arraycopy(signature1Bytes, 0, dbPayload, pos, signature1Bytes.length);
        pos += signature1Bytes.length;
        System.arraycopy(signature2Bytes, 0, dbPayload, pos, signature2Bytes.length);

        // --- Build DB request JSON ---
        ObjectNode dbRequest = jsonMapper.createObjectNode();
        dbRequest.put("sql", 0);
        dbRequest.put("id", id);
        dbRequest.put("source", source);
        dbRequest.put("destination", destination);
        dbRequest.put("seller", seller);
        dbRequest.put("buyer", buyer);
        // Add any other header fields as needed

        // --- Send to DB and handle response ---
        try {
            byte[] dbRequestBytes = jsonMapper.writeValueAsBytes(dbRequest);
            // Append dbPayload to dbRequestBytes
            byte[] combined = new byte[dbRequestBytes.length + dbPayload.length];
            System.arraycopy(dbRequestBytes, 0, combined, 0, dbRequestBytes.length);
            System.arraycopy(dbPayload, 0, combined, dbRequestBytes.length, dbPayload.length);
            byte[] dbResponse = sendDatabaseRequest(combined);
            if (dbResponse == null) {
                return errorResponse("Database did not respond");
            }
            return dbResponse;
        } catch (Exception e) {
            return errorResponse("Database request failed: " + e.getMessage());
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
            byte[] allRequestBytes = jsonMapper.writeValueAsBytes(getAllRequest);
            byte[] allBytes = sendDatabaseRequest(allRequestBytes);
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
            byte[] getRequestBytes = jsonMapper.writeValueAsBytes(getRequest);
            byte[] recBytes = sendDatabaseRequest(getRequestBytes);
            if (recBytes == null) {
                return errorResponse("Transaction not found");
            }
            
            ObjectNode sharesRequest = jsonMapper.createObjectNode();
            sharesRequest.put("sql", 2);
            sharesRequest.put("transactionId", id);
            byte[] sharesRequestBytes = jsonMapper.writeValueAsBytes(sharesRequest);
            byte[] sharesBytes = sendDatabaseRequest(sharesRequestBytes);
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
            byte[] shareRecordsRequestBytes = jsonMapper.writeValueAsBytes(shareRecordsRequest);
            byte[] shareRecordsBytes = sendDatabaseRequest(shareRecordsRequestBytes);
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
            byte[] sharesRequestBytes = jsonMapper.writeValueAsBytes(sharesRequest);
            byte[] sharesBytes = sendDatabaseRequest(sharesRequestBytes);
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
            byte[] getByRequestBytes = jsonMapper.writeValueAsBytes(getByRequest);
            byte[] sharesByBytes = sendDatabaseRequest(getByRequestBytes);
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
     * Helper: Send JSON request to database server over TCP and get response.
     */
    private byte[] sendDatabaseRequest(byte[] request) throws Exception {
        byte[] resp= null;
        try {
            resp = ApiCalls.actAsSender(dbHost, dbPort, "server", 0, "db", request);
        } catch (Throwable t) {
            System.out.println("DEBUG: sendDatabaseRequest threw: " + t.getMessage());
            throw t;
        }
        return resp;
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

}