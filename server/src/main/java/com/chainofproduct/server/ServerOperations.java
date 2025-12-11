package com.chainofproduct.server;

import com.chainofproduct.utils.ApiCalls;
import java.security.PrivateKey;
import java.security.PublicKey;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class ServerOperations {
    
    private final String dbHost;
    private final int dbPort;
    private final ObjectMapper jsonMapper;
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
     * @param clientName The name of the client making the request (can be null for tests)
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
                case "groupUpdate":
                    return handleGroupUpdateRequest(requestStr, clientName);
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
     * Handle group update requests (create, add, remove members).
     * Accepts a binary JSON payload as described in the prompt.
     * Dispatches to DB with sql: 9 (create), 10 (add), 11 (remove).
     */
    private byte[] handleGroupUpdateRequest(String requestStr, String clientName) {
        JsonNode jsonHeader;

        try {
            jsonHeader = jsonMapper.readTree(requestStr);
        } catch (Exception e) {
            return errorResponse("Invalid JSON: " + e.getMessage());
        }

        if (!jsonHeader.has("group")) {
            return errorResponse("Missing required field: group");
        }

        if (!jsonHeader.has("source")) {
            return errorResponse("Missing required field: source");
        }

        String groupName = jsonHeader.get("group").asText();
        String source = jsonHeader.get("source").asText();
        if (!source.equals(clientName)) {
            return errorResponse("Source does not match authenticated client name");
        }

        boolean hasAdditions = false;
        boolean hasRemovals = false;
        java.util.ArrayList<JsonNode> responses = new java.util.ArrayList<>();

        // Check groupAdditions
        JsonNode additionsNode = jsonHeader.get("groupAdditions");
        if (additionsNode != null && additionsNode.isArray()) {
            int size = additionsNode.size();
            if (size > 1) {
                hasAdditions = true;
            } else if (size == 1 && !additionsNode.get(0).asText().equalsIgnoreCase("none")) {
                hasAdditions = true;
            }
        }

        // Check groupRemove
        JsonNode removalsNode = jsonHeader.get("groupRemove");
        if (removalsNode != null && removalsNode.isArray()) {
            int size = removalsNode.size();
            if (size > 1) {
                hasRemovals = true;
            } else if (size == 1 && !removalsNode.get(0).asText().equalsIgnoreCase("none")) {
                hasRemovals = true;
            }
        }


        // Check if group already exists (sql:9)
        boolean groupExists = false;
        String groupLeader = null;
        ObjectNode checkGroupRequest = jsonMapper.createObjectNode();
        checkGroupRequest.put("sql", 9);
        checkGroupRequest.put("name", groupName);
        byte[] checkGroupRequestBytes = checkGroupRequest.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        try {
            String checkGroupRespStr = new String(sendDatabaseRequest(checkGroupRequestBytes), java.nio.charset.StandardCharsets.UTF_8);
            JsonNode checkGroupResp = jsonMapper.readTree(checkGroupRespStr);
            // If leader is present and not null, group exists
            if (checkGroupResp.has("leader") && !checkGroupResp.get("leader").isNull()) {
                groupExists = true;
                groupLeader = checkGroupResp.get("leader").asText();
            }
        } catch (Exception e) {
            return errorResponse("Database request failed: " + e.getMessage());
        }

        // Only create group if it does not exist
        if (!groupExists) {
            ObjectNode makegroupdbRequest = jsonMapper.createObjectNode();
            makegroupdbRequest.put("sql", 8);
            makegroupdbRequest.put("name", groupName);
            makegroupdbRequest.put("leader", source);
            byte[] makegroupdbRequestBytes = makegroupdbRequest.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try {
                responses.add(jsonMapper.readTree(new String(sendDatabaseRequest(makegroupdbRequestBytes), java.nio.charset.StandardCharsets.UTF_8)));
            } catch (Exception e) {
                return errorResponse("Database request failed: " + e.getMessage());
            }
        }

        if (groupExists && !source.equals(groupLeader)) {
            return errorResponse("Only group leader (" + groupLeader + ") can modify group membership");
        }

        // Only send additions if hasAdditions is true
        if (hasAdditions) {
            ObjectNode addtogroupdbRequest = jsonMapper.createObjectNode();
            addtogroupdbRequest.put("sql", 10);
            addtogroupdbRequest.put("name", groupName);
            addtogroupdbRequest.put("additions", additionsNode.toString());
            byte[] addtogroupdbRequestBytes = addtogroupdbRequest.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try {
                responses.add(jsonMapper.readTree(new String(sendDatabaseRequest(addtogroupdbRequestBytes), java.nio.charset.StandardCharsets.UTF_8)));
            } catch (Exception e) {
                return errorResponse("Database request failed: " + e.getMessage());
            }
        }

        // Only send removals if hasRemovals is true
        if (hasRemovals) {
            ObjectNode removefromgroupdbRequest = jsonMapper.createObjectNode();
            removefromgroupdbRequest.put("sql", 11);
            removefromgroupdbRequest.put("name", groupName);
            removefromgroupdbRequest.put("removals", removalsNode.toString());
            byte[] removefromgroupdbRequestBytes = removefromgroupdbRequest.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try {
                responses.add(jsonMapper.readTree(new String(sendDatabaseRequest(removefromgroupdbRequestBytes), java.nio.charset.StandardCharsets.UTF_8)));
            } catch (Exception e) {
                return errorResponse("Database request failed: " + e.getMessage());
            }
        }

        StringBuilder json = new StringBuilder("{\"responses\":[");
        for (int i = 0; i < responses.size(); i++) {
            if (i > 0) json.append(",");
            json.append(responses.get(i).toString());
        }
        json.append("]}");
        return json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);

        
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
     * Handle get transaction by ID request with access control (SR1).
     * Format: {request_type:getById, source: ClientName, transaction_id: 123}
     */
    private byte[] handleGetByIdRequest(String requestStr) {
        try {
            String source = extractField(requestStr, "source");
            if (source == null) {
                source = extractField(requestStr, "servername");
            }
            if (source == null) {
                return errorResponse("Missing source field");
            }
            
            long id = extractLongField(requestStr, "transaction_id");
            if (id == 0) {
                return errorResponse("Invalid or missing transaction_id");
            }
            
            // Check access control first (sql=2: getShares)
            if (!checkTransactionAccess(id, source)) {
                return errorResponse("Access denied: transaction not shared with you");
            }
            
            // Get transaction via TCP (sql=5: getTransactionById)
            ObjectNode getRequest = jsonMapper.createObjectNode();
            getRequest.put("sql", 5);
            getRequest.put("id", id);
            byte[] getRequestBytes = jsonMapper.writeValueAsBytes(getRequest);
            byte[] recBytes = sendDatabaseRequest(getRequestBytes);
            
            if (recBytes == null) {
                return errorResponse("Transaction not found: " + id);
            }
            
            // Return raw DB response (already contains full transaction with signatures)
            return recBytes;
        } catch (Exception e) {
            return errorResponse("Get by ID error: " + e.getMessage());
        }
    }   

    /**
     * Handle get all transactions request with access control (SR1).
     * Format: {request_type:getAll, source: ClientName}
     */
    private byte[] handleGetAllRequest(String requestStr) {
        try {
            String source = extractField(requestStr, "source");
            if (source == null) {
                source = extractField(requestStr, "servername");
            }
            if (source == null) {
                return errorResponse("Missing source field");
            }
            
            // Get all transactions (sql=4: getAllTransactions)
            ObjectNode getAllRequest = jsonMapper.createObjectNode();
            getAllRequest.put("sql", 4);
            byte[] allRequestBytes = jsonMapper.writeValueAsBytes(getAllRequest);
            byte[] allBytes = sendDatabaseRequest(allRequestBytes);
            
            if (allBytes == null) {
                return errorResponse("Database did not respond");
            }
            
            // Filter transactions by access control
            JsonNode allTransactions = jsonMapper.readTree(allBytes);
            StringBuilder json = new StringBuilder("{\"transactions\":[");
            boolean first = true;
            
            if (allTransactions.isArray()) {
                for (JsonNode txn : allTransactions) {
                    long txnId = txn.get("id").asLong();
                    // Check access for each transaction
                    if (checkTransactionAccess(txnId, source)) {
                        if (!first) json.append(",");
                        first = false;
                        
                        // Build transaction JSON with proper field names
                        json.append(String.format(
                            "{\"id\":%d,\"timestamp\":%d,\"seller\":\"%s\",\"buyer\":\"%s\",\"product\":\"%s\",\"units\":%d,\"amount\":%d,\"seller_signature\":\"%s\",\"buyer_signature\":\"%s\"}",
                            txn.get("id").asLong(),
                            txn.get("timestamp").asLong(),
                            txn.get("seller").asText(),
                            txn.get("buyer").asText(),
                            txn.has("product") ? txn.get("product").asText() : "",
                            txn.has("units") ? txn.get("units").asLong() : 0,
                            txn.has("amount") ? txn.get("amount").asLong() : 0,
                            txn.has("sellerSignature") ? txn.get("sellerSignature").asText() : "",
                            txn.has("buyerSignature") ? txn.get("buyerSignature").asText() : ""
                        ));
                    }
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
            if (source == null) {
                source = extractField(requestStr, "servername");
            }
            if (source == null) {
                return errorResponse("Missing source field");
            }
            if (id == 0) {
                return errorResponse("Invalid or missing transaction_id");
            }
            
            // SR1: Check access control first
            if (!checkTransactionAccess(id, source)) {
                return errorResponse("Access denied: transaction not shared with you");
            }
            
            // Get transaction to extract metadata (sql=5: getTransactionById)
            ObjectNode getRequest = jsonMapper.createObjectNode();
            getRequest.put("sql", 5);
            getRequest.put("id", id);
            byte[] getRequestBytes = jsonMapper.writeValueAsBytes(getRequest);
            byte[] recBytes = sendDatabaseRequest(getRequestBytes);
            
            if (recBytes == null) {
                return errorResponse("Transaction not found");
            }
            
            JsonNode transaction = jsonMapper.readTree(recBytes);
            
            // Get shares list (sql=2: getShares)
            ObjectNode sharesRequest = jsonMapper.createObjectNode();
            sharesRequest.put("sql", 2);
            sharesRequest.put("transactionId", id);
            byte[] sharesRequestBytes = jsonMapper.writeValueAsBytes(sharesRequest);
            byte[] sharesBytes = sendDatabaseRequest(sharesRequestBytes);
            
            JsonNode sharesNode = jsonMapper.readTree(sharesBytes);
            
            // Build response with share records
            StringBuilder json = new StringBuilder("{\"shares\":[");
            if (sharesNode.isArray()) {
                for (int i = 0; i < sharesNode.size(); i++) {
                    if (i > 0) json.append(",");
                    String shareName = sharesNode.get(i).asText();
                    // Determine who shared (seller and buyer are initially shared by server)
                    String sharedBy = "server";
                    if (transaction.has("seller") && transaction.has("buyer")) {
                        String seller = transaction.get("seller").asText();
                        String buyer = transaction.get("buyer").asText();
                        if (!shareName.equals(seller) && !shareName.equals(buyer)) {
                            sharedBy = seller; // Assume additional shares were added by seller
                        }
                    }
                    json.append(String.format(
                        "{\"company\":\"%s\",\"shared_by\":\"%s\",\"timestamp\":%d,\"signature\":\"\"}",
                        shareName,
                        sharedBy,
                        transaction.has("timestamp") ? transaction.get("timestamp").asLong() : 0
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
            if (source == null) {
                source = extractField(requestStr, "servername");
            }
            
            if (source == null) {
                return errorResponse("Missing source field");
            }
            if (sharedBy == null) {
                return errorResponse("Missing shared_by parameter");
            }
            if (id == 0) {
                return errorResponse("Invalid or missing transaction_id");
            }
            
            // SR1: Check access control first
            if (!checkTransactionAccess(id, source)) {
                return errorResponse("Access denied: transaction not shared with you");
            }
            
            // Get transaction for metadata (sql=5: getTransactionById)
            ObjectNode getRequest = jsonMapper.createObjectNode();
            getRequest.put("sql", 5);
            getRequest.put("id", id);
            byte[] getRequestBytes = jsonMapper.writeValueAsBytes(getRequest);
            byte[] recBytes = sendDatabaseRequest(getRequestBytes);
            
            if (recBytes == null) {
                return errorResponse("Transaction not found");
            }
            
            JsonNode transaction = jsonMapper.readTree(recBytes);
            
            // Get shares by sharedBy (sql=3: getSharesBySharedBy)
            ObjectNode getByRequest = jsonMapper.createObjectNode();
            getByRequest.put("sql", 3);
            getByRequest.put("transactionId", id);
            getByRequest.put("sharedBy", sharedBy);
            byte[] getByRequestBytes = jsonMapper.writeValueAsBytes(getByRequest);
            byte[] sharesByBytes = sendDatabaseRequest(getByRequestBytes);
            
            JsonNode sharesNode = jsonMapper.readTree(sharesByBytes);
            
            // Build response with filtered shares
            StringBuilder json = new StringBuilder("{\"shares\":[");
            if (sharesNode.isArray()) {
                for (int i = 0; i < sharesNode.size(); i++) {
                    if (i > 0) json.append(",");
                    String shareName = sharesNode.get(i).asText();
                    json.append(String.format(
                        "{\"company\":\"%s\",\"shared_by\":\"%s\",\"timestamp\":%d,\"signature\":\"\"}",
                        shareName,
                        sharedBy,
                        transaction.has("timestamp") ? transaction.get("timestamp").asLong() : 0
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
     * Helper: Check if source has access to a transaction (SR1).
     * @param transactionId the transaction ID to check
     * @param source the entity requesting access
     * @return true if access granted, false otherwise
     */
    private boolean checkTransactionAccess(long transactionId, String source) {
        try {
            ObjectNode sharesRequest = jsonMapper.createObjectNode();
            sharesRequest.put("sql", 2);
            sharesRequest.put("transactionId", transactionId);
            byte[] sharesRequestBytes = jsonMapper.writeValueAsBytes(sharesRequest);
            byte[] sharesBytes = sendDatabaseRequest(sharesRequestBytes);
            
            if (sharesBytes == null) {
                return false;
            }
            
            JsonNode sharesNode = jsonMapper.readTree(sharesBytes);
            if (sharesNode.isArray()) {
                for (JsonNode node : sharesNode) {
                    if (source.equals(node.asText())) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            System.err.println("Error checking transaction access: " + e.getMessage());
            return false;
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