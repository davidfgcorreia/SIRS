package com.chainofproduct.server;

import com.chainofproduct.db.DatabaseOperations;
import com.chainofproduct.utils.CryptoUtils;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.SQLException;
import java.util.Base64;
import java.util.List;

/**
 * ServerOperations - handles all client requests in centralized architecture with full security.
 * Implements SR1-SR4 security requirements for Chain of Product.
 */
public class ServerOperations {
    private final String serverName;
    private final PrivateKey serverPrivateKey;
    private final SecretKey storageKey; // For encrypting transactions at rest (SR1)

    public ServerOperations() throws Exception {
        this.serverName = DatabaseOperations.getServerName();
        // Load server's private key for signing share operations
        this.serverPrivateKey = CryptoUtils.loadPrivateKey("keys/server-private.key");
        // Load or generate storage encryption key for database
        this.storageKey = loadOrGenerateStorageKey();
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
            System.out.println("Processing request: " + requestStr.substring(0, Math.min(200, requestStr.length())));
            
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
     * Handle transaction submission from client with signatures (SR3).
     * Format: {request_type: transaction, source: ClientName}[JSON_DATA]{seller_sig:...}{buyer_sig:...}
     */
    private byte[] handleTransactionRequest(String requestStr, byte[] fullRequest) {
        try {
            // Extract source (who's submitting)
            String source = extractField(requestStr, "source");
            if (source == null) {
                return errorResponse("Missing source field");
            }
            
            // Find where the metadata ends and JSON transaction data begins
            int jsonStart = requestStr.indexOf("}") + 1;
            if (jsonStart >= fullRequest.length) {
                return errorResponse("No transaction data provided");
            }
            
            // Extract the full payload after metadata
            String payload = new String(fullRequest, jsonStart, fullRequest.length - jsonStart, 
                java.nio.charset.StandardCharsets.UTF_8);
            
            // Split payload into: transaction JSON, seller_signature, buyer_signature
            // Format: {...transaction...}{seller_sig:BASE64}{buyer_sig:BASE64}
            int sigStart = payload.lastIndexOf("}{seller_sig:");
            if (sigStart == -1) {
                return errorResponse("Missing seller signature");
            }
            String transactionJson = payload.substring(0, sigStart + 1);
            String sigPart = payload.substring(sigStart + 1);
            
            String sellerSig = extractField(sigPart, "seller_sig");
            String buyerSig = extractField(sigPart, "buyer_sig");
            
            if (sellerSig == null || buyerSig == null) {
                return errorResponse("Missing transaction signatures");
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
            
            // SR3: Verify signatures
            byte[] transactionBytes = transactionJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            PublicKey sellerPubKey = getCompanyPublicKey(seller);
            PublicKey buyerPubKey = getCompanyPublicKey(buyer);
            
            if (!CryptoUtils.verifySignature(transactionBytes, sellerSig, sellerPubKey)) {
                return errorResponse("Invalid seller signature");
            }
            if (!CryptoUtils.verifySignature(transactionBytes, buyerSig, buyerPubKey)) {
                return errorResponse("Invalid buyer signature");
            }
            
            System.out.println("Storing transaction: id=" + id + ", seller=" + seller + ", buyer=" + buyer);
            
            // SR1: Encrypt transaction before storing
            byte[] encryptedData = CryptoUtils.encrypt(transactionBytes, storageKey);
            String encryptedB64 = Base64.getEncoder().encodeToString(encryptedData);
            
            // Store in database with signatures
            DatabaseOperations.insertTransaction(id, timestamp, seller, buyer, product, units, amount,
                                                  sellerSig, buyerSig, encryptedB64);
            
            // SR4: Add initial shares with server signature
            long shareTime = System.currentTimeMillis();
            String shareData = String.format("%d:%s:server", id, seller);
            String sellerShareSig = CryptoUtils.signData(shareData.getBytes(), serverPrivateKey);
            DatabaseOperations.addShare(id, seller, "server", shareTime, sellerShareSig);
            
            shareData = String.format("%d:%s:server", id, buyer);
            String buyerShareSig = CryptoUtils.signData(shareData.getBytes(), serverPrivateKey);
            DatabaseOperations.addShare(id, buyer, "server", shareTime, buyerShareSig);
            
            return successResponse("Transaction stored successfully with id=" + id);
            
        } catch (SQLException e) {
            return errorResponse("Database error: " + e.getMessage());
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
            
            // Get transaction to verify access
            DatabaseOperations.TransactionRecord rec = DatabaseOperations.getTransactionById(id);
            if (rec == null) {
                return errorResponse("Transaction not found");
            }
            
            // SR2: Only seller or buyer can share
            if (!source.equals(rec.seller) && !source.equals(rec.buyer)) {
                return errorResponse("Access denied: only seller or buyer can share this transaction");
            }
            
            // Verify signature on share request
            String shareData = String.format("%d:%s:%s", id, shareWith, source);
            PublicKey sourcePubKey = getCompanyPublicKey(source);
            if (!CryptoUtils.verifySignature(shareData.getBytes(), signature, sourcePubKey)) {
                return errorResponse("Invalid share signature");
            }
            
            // SR4: Add share with cryptographic proof
            long shareTime = System.currentTimeMillis();
            DatabaseOperations.addShare(id, shareWith, source, shareTime, signature);
            
            return successResponse("Transaction shared with " + shareWith);
            
        } catch (SQLException e) {
            return errorResponse("Database error: " + e.getMessage());
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
            
            DatabaseOperations.TransactionRecord rec = DatabaseOperations.getTransactionById(id);
            if (rec == null) {
                return errorResponse("Transaction not found: " + id);
            }
            
            // SR1: Check if requester has access (must be seller, buyer, or someone it was shared with)
            List<String> shares = DatabaseOperations.getShares(id);
            if (!shares.contains(source)) {
                return errorResponse("Access denied: transaction not shared with you");
            }
            
            // Return transaction with signatures for verification (SR3)
            String json = String.format(
                "{\"id\":%d,\"timestamp\":%d,\"seller\":\"%s\",\"buyer\":\"%s\",\"product\":\"%s\",\"units\":%d,\"amount\":%d,\"seller_signature\":\"%s\",\"buyer_signature\":\"%s\"}",
                rec.id, rec.timestamp, rec.seller, rec.buyer, rec.product, rec.units, rec.amount, rec.sellerSignature, rec.buyerSignature
            );
            
            return json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
        } catch (SQLException e) {
            return errorResponse("Database error: " + e.getMessage());
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
            
            List<DatabaseOperations.TransactionRecord> allRecords = DatabaseOperations.getAllTransactions();
            
            StringBuilder json = new StringBuilder("{\"transactions\":[");
            boolean first = true;
            for (DatabaseOperations.TransactionRecord rec : allRecords) {
                // SR1: Only return transactions that were shared with this source
                List<String> shares = DatabaseOperations.getShares(rec.id);
                if (shares.contains(source)) {
                    if (!first) json.append(",");
                    first = false;
                    json.append(String.format(
                        "{\"id\":%d,\"timestamp\":%d,\"seller\":\"%s\",\"buyer\":\"%s\",\"product\":\"%s\",\"units\":%d,\"amount\":%d,\"seller_signature\":\"%s\",\"buyer_signature\":\"%s\"}",
                        rec.id, rec.timestamp, rec.seller, rec.buyer, rec.product, rec.units, rec.amount, rec.sellerSignature, rec.buyerSignature
                    ));
                }
            }
            json.append("]}");
            
            return json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
        } catch (SQLException e) {
            return errorResponse("Database error: " + e.getMessage());
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
            
            // SR1: Check access
            DatabaseOperations.TransactionRecord rec = DatabaseOperations.getTransactionById(id);
            if (rec == null) {
                return errorResponse("Transaction not found");
            }
            List<String> shares = DatabaseOperations.getShares(id);
            if (!shares.contains(source)) {
                return errorResponse("Access denied: transaction not shared with you");
            }
            
            // SR4: Return share records with cryptographic proof
            List<DatabaseOperations.ShareRecord> shareRecords = DatabaseOperations.getShareRecords(id);
            
            StringBuilder json = new StringBuilder("{\"shares\":[");
            for (int i = 0; i < shareRecords.size(); i++) {
                if (i > 0) json.append(",");
                DatabaseOperations.ShareRecord sr = shareRecords.get(i);
                json.append(String.format(
                    "{\"company\":\"%s\",\"shared_by\":\"%s\",\"timestamp\":%d,\"signature\":\"%s\"}",
                    sr.share, sr.sharedBy, sr.timestamp, sr.signature
                ));
            }
            json.append("]}");
            
            return json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
        } catch (SQLException e) {
            return errorResponse("Database error: " + e.getMessage());
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
            
            // SR1: Check access
            List<String> shares = DatabaseOperations.getShares(id);
            if (!shares.contains(source)) {
                return errorResponse("Access denied: transaction not shared with you");
            }
            
            // SR4: Return share records with cryptographic proof
            List<DatabaseOperations.ShareRecord> shareRecords = DatabaseOperations.getShareRecordsBySharedBy(id, sharedBy);
            
            StringBuilder json = new StringBuilder("{\"shares\":[");
            for (int i = 0; i < shareRecords.size(); i++) {
                if (i > 0) json.append(",");
                DatabaseOperations.ShareRecord sr = shareRecords.get(i);
                json.append(String.format(
                    "{\"company\":\"%s\",\"shared_by\":\"%s\",\"timestamp\":%d,\"signature\":\"%s\"}",
                    sr.share, sr.sharedBy, sr.timestamp, sr.signature
                ));
            }
            json.append("]}");
            
            return json.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
        } catch (SQLException e) {
            return errorResponse("Database error: " + e.getMessage());
        } catch (Exception e) {
            return errorResponse("Get shares by error: " + e.getMessage());
        }
    }
    
    /**
     * Helper: Load public key for a company.
     */
    private PublicKey getCompanyPublicKey(String companyName) throws Exception {
        DatabaseOperations.CompanyInfo info = DatabaseOperations.getCompanyInfo(companyName);
        if (info == null) {
            throw new IllegalArgumentException("Unknown company: " + companyName);
        }
        return CryptoUtils.loadPublicKey(info.publicKey);
    }

    // Helper methods for simple string parsing
    private String extractField(String str, String fieldName) {
        String pattern = fieldName + ":";
        int start = str.indexOf(pattern);
        if (start == -1) return null;
        start += pattern.length();
        
        // Skip whitespace and quotes
        while (start < str.length() && (str.charAt(start) == ' ' || str.charAt(start) == '"')) start++;
        
        // Find end (comma, brace, or quote)
        int end = start;
        boolean inQuotes = false;
        while (end < str.length()) {
            char c = str.charAt(end);
            if (c == '"') inQuotes = !inQuotes;
            else if (!inQuotes && (c == ',' || c == '}')) break;
            end++;
        }
        
        String value = str.substring(start, end).trim();
        // Remove quotes if present
        if (value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }
        return value.isEmpty() ? null : value;
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
