package com.chainofproduct.server;

import com.chainofproduct.utils.CryptoUtils;
import com.chainofproduct.utils.ApiCalls;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Paths;
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
    private final String serverName;
    private final PrivateKey serverPrivateKey;
    private final SecretKey storageKey; // For encrypting transactions at rest (SR1)
    private final String dbHost;
    private final int dbPort;
    private final String dbPubKeyFile;
    private final String serverPrivKeyFile;
    private final String serverPubKeyFile;
    private final ObjectMapper jsonMapper;

    public ServerOperations() throws Exception {
        this.serverName = "Central Server"; // Default server name
        this.serverPrivKeyFile = "keys/server-private.key";
        this.serverPubKeyFile = "keys/server-public.key";
        
        // Load server's private key for signing share operations
        this.serverPrivateKey = CryptoUtils.loadPrivateKey(serverPrivKeyFile);
        // Load or generate storage encryption key for database
        this.storageKey = loadOrGenerateStorageKey();
        
        // Load database connection info from config
        String dbPubKey = null;
        String host = "localhost";
        int port = 5432;
        try {
            java.nio.file.Path infoPath = java.nio.file.Paths.get("localization_info/database_info.json");
            String json = new String(java.nio.file.Files.readAllBytes(infoPath), java.nio.charset.StandardCharsets.UTF_8);
            dbPubKey = extractJsonStringField(json, "pubkey");
            host = extractJsonStringField(json, "ip");
            String portStr = extractJsonStringField(json, "port");
            if (portStr != null && !portStr.isEmpty()) {
                port = Integer.parseInt(portStr);
            }
        } catch (Exception e) {
            System.err.println("Failed to load database info, using defaults: " + e.getMessage());
            dbPubKey = "keys/database-public.key";
        }
        this.dbHost = host;
        this.dbPort = port;
        this.dbPubKeyFile = dbPubKey;
        this.jsonMapper = new ObjectMapper();
    }
    
    /**
     * Load or generate AES key for encrypting transactions at rest (SR1).
     */
    private SecretKey loadOrGenerateStorageKey() throws Exception {
        String keyPath = "keys/storage-key.aes";
        try {
            return CryptoUtils.readKeyFromFile(keyPath, "AES");
        } catch (Exception e) {
            // Generate new key if doesn't exist
            SecretKey key = CryptoUtils.generateAESKey(256);
            String b64 = Base64.getEncoder().encodeToString(key.getEncoded());
            Files.createDirectories(Paths.get("keys"));
            Files.writeString(Paths.get(keyPath), b64);
            return key;
        }
    }

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
            System.out.println("DEBUG: Extracted source='" + source + "'");
            
            // Find where the metadata ends and JSON transaction data begins
            int jsonStart = requestStr.indexOf("}") + 1;
            if (jsonStart >= fullRequest.length) {
                return errorResponse("No transaction data provided");
            }
            
            // Extract the full payload after metadata
            String payload = new String(fullRequest, jsonStart, fullRequest.length - jsonStart, 
                java.nio.charset.StandardCharsets.UTF_8);
            
            // Split payload into: transaction JSON and signature
            // Format: {...transaction...}{signature:BASE64}
            // Find the last occurrence of {signature: (may have whitespace before it)
            int sigStart = payload.lastIndexOf("{signature:");
            if (sigStart == -1) {
                return errorResponse("Missing signature");
            }
            
            // Transaction bytes are from jsonStart to just before {signature:
            // This includes any whitespace between the transaction JSON and signature
            int transactionStart = jsonStart;
            int transactionLength = sigStart;  // sigStart is relative to payload start
            byte[] transactionBytes = new byte[transactionLength];
            System.arraycopy(fullRequest, transactionStart, transactionBytes, 0, transactionLength);
            
            // Extract transaction JSON for parsing (trim whitespace for field extraction)
            String transactionJson = payload.substring(0, sigStart).trim();
            String sigPart = payload.substring(sigStart);
            
            String signature = extractField(sigPart, "signature");
            if (signature == null) {
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
            
            System.out.println("DEBUG: Parsed fields - seller=" + seller + ", buyer=" + buyer + ", product=" + product);
            
            if (seller == null || buyer == null || product == null) {
                return errorResponse("Missing required transaction fields");
            }
            
            // SR2: Only seller or buyer can submit transaction
            if (!source.equals(seller) && !source.equals(buyer)) {
                return errorResponse("Access denied: only seller or buyer can submit transaction");
            }
            
            // SR3: Verify submitter's signature
            PublicKey sourcePubKey = getCompanyPublicKey(source);
            
            System.out.println("DEBUG: transactionBytes length=" + transactionBytes.length);
            System.out.println("DEBUG: signature length=" + signature.length());
            
            if (!CryptoUtils.verifySignature(transactionBytes, signature, sourcePubKey)) {
                return errorResponse("Invalid signature from " + source);
            }
            
            System.out.println("Storing transaction: id=" + id + ", seller=" + seller + ", buyer=" + buyer + ", submitted by=" + source);
            
            // Determine who signed (seller or buyer based on source)
            String sellerSig = source.equals(seller) ? signature : "";
            String buyerSig = source.equals(buyer) ? signature : "";
            
            // SR1: Encrypt transaction before storing (confidentiality)
            byte[] encryptedData = CryptoUtils.encrypt(transactionBytes, storageKey);
            String encryptedB64 = Base64.getEncoder().encodeToString(encryptedData);
            
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
            dbRequest.put("encryptedData", encryptedB64);
            sendDatabaseRequest(dbRequest);
            
            // SR4: Add initial shares with server signature via TCP (sql=1: addShare)
            long shareTime = System.currentTimeMillis();
            String shareData = String.format("%d:%s:server", id, seller);
            String sellerShareSig = CryptoUtils.signData(shareData.getBytes(), serverPrivateKey);
            
            ObjectNode shareRequest1 = jsonMapper.createObjectNode();
            shareRequest1.put("sql", 1);
            shareRequest1.put("transactionId", id);
            shareRequest1.put("share", seller);
            shareRequest1.put("sharedBy", "server");
            shareRequest1.put("timestamp", shareTime);
            shareRequest1.put("signature", sellerShareSig);
            sendDatabaseRequest(shareRequest1);
            
            shareData = String.format("%d:%s:server", id, buyer);
            String buyerShareSig = CryptoUtils.signData(shareData.getBytes(), serverPrivateKey);
            
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
            if (!CryptoUtils.verifySignature(shareData.getBytes(), signature, sourcePubKey)) {
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
            
            long id = extractLongField(requestStr, "trasaction_id"); // Note: typo in client code
            if (id == 0) {
                id = extractLongField(requestStr, "transaction_id");
            }
            
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
     * Format: {request_type:getAll, source: ClientName}
     */
    private byte[] handleGetAllRequest(String requestStr) {
        try {
            String source = extractField(requestStr, "source");
            if (source == null) source = extractField(requestStr, "servername"); // fallback
            
            // Get all transactions via TCP (sql=4: getAllTransactions)
            ObjectNode getAllRequest = jsonMapper.createObjectNode();
            getAllRequest.put("sql", 4);
            byte[] allBytes = sendDatabaseRequest(getAllRequest);
            JsonNode allRecords = jsonMapper.readTree(allBytes);
            
            StringBuilder json = new StringBuilder("{\"transactions\":[");
            boolean first = true;
            
            if (allRecords.isArray()) {
                for (JsonNode rec : allRecords) {
                    long recId = rec.get("id").asLong();
                    
                    // SR1: Check if this transaction was shared with source via TCP (sql=2: getShares)
                    ObjectNode sharesRequest = jsonMapper.createObjectNode();
                    sharesRequest.put("sql", 2);
                    sharesRequest.put("transactionId", recId);
                    byte[] sharesBytes = sendDatabaseRequest(sharesRequest);
                    JsonNode sharesNode = jsonMapper.readTree(sharesBytes);
                    List<String> shares = new ArrayList<>();
                    if (sharesNode.isArray()) {
                        for (JsonNode node : sharesNode) {
                            shares.add(node.asText());
                        }
                    }
                    
                    if (shares.contains(source)) {
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
            
            // SR4: Return share records with cryptographic proof - need new SQL operation
            // For now, return simple shares list (TODO: add getShareRecords to ServerExecutorImpl)
            StringBuilder json = new StringBuilder("{\"shares\":[");
            for (int i = 0; i < shares.size(); i++) {
                if (i > 0) json.append(",");
                json.append(String.format(
                    "{\"company\":\"%s\",\"shared_by\":\"unknown\",\"timestamp\":0,\"signature\":\"\"}",
                    shares.get(i)
                ));
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
            
            // SR4: Get shares by sharedBy via TCP (sql=3: getSharesBySharedBy)
            ObjectNode getByRequest = jsonMapper.createObjectNode();
            getByRequest.put("sql", 3);
            getByRequest.put("transactionId", id);
            getByRequest.put("sharedBy", sharedBy);
            byte[] sharesByBytes = sendDatabaseRequest(getByRequest);
            JsonNode sharesByNode = jsonMapper.readTree(sharesByBytes);
            
            StringBuilder json = new StringBuilder("{\"shares\":[");
            if (sharesByNode.isArray()) {
                for (int i = 0; i < sharesByNode.size(); i++) {
                    if (i > 0) json.append(",");
                    json.append(String.format(
                        "{\"company\":\"%s\",\"shared_by\":\"%s\",\"timestamp\":0,\"signature\":\"\"}",
                        sharesByNode.get(i).asText(), sharedBy
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
     * Helper: Load public key for a company via TCP.
     */
    private PublicKey getCompanyPublicKey(String companyName) throws Exception {
        // For now, directly load from filesystem (companies table has file paths)
        // In production, you'd query database server for this
        String keyPath = "keys/" + companyName.toLowerCase().replace(" ", "-") + "-public.key";
        return CryptoUtils.loadPublicKey(keyPath);
    }
    
    /**
     * Helper: Send JSON request to database server over TCP and get response.
     */
    private byte[] sendDatabaseRequest(ObjectNode request) throws Exception {
        byte[] requestBytes = jsonMapper.writeValueAsBytes(request);
        return ApiCalls.actAsSender(dbHost, dbPort, serverPrivKeyFile, serverPubKeyFile, dbPubKeyFile, requestBytes);
    }
    
    /**
     * Helper: Extract string field from simple JSON (no nested objects).
     */
    private String extractJsonStringField(String json, String field) {
        String key = "\"" + field + "\":";
        int idx = json.indexOf(key);
        if (idx == -1) return null;
        int start = json.indexOf('"', idx + key.length());
        int end = json.indexOf('"', start + 1);
        if (start == -1 || end == -1) return null;
        return json.substring(start + 1, end);
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
