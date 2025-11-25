package com.chainofproduct.server;

import com.chainofproduct.db.DatabaseOperations;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadLocalRandom;

/**
 * ServerOperations - fills TODOs:
 *  - handleSendTransaction: resolve destination, optionally insert a transaction row,
 *    create a Request and enqueue it for sender manager.
 *  - handleTransactionRequest / handleShareRequest: enqueue requests and notify sender manager.
 *  - handleReceiveTransaction / handleReceiveShare: process decrypted payloads and store in DB.
 */
public class ServerOperations {
    private final BlockingQueue<Request> sendQueue;
    private final Object sendLock;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ServerOperations(BlockingQueue<Request> sendQueue, Object sendLock) {
        this.sendQueue = sendQueue;
        this.sendLock = sendLock;
    }

    /**
     * Handle send transaction with proper validation and share checking.
     * 
     * Flow:
     * 1. Parse and validate JSON transaction data
     * 2. Confirm server is buyer or seller
     * 3. Resolve destination info from database
     * 4. Store transaction in the database
     * 5. Check for required shares
     * 6. If shares missing, forward to other party for share generation
     * 7. Enqueue request for sending
     * 
     * Destination can be either:
     * - Company name (resolved from DB)
     * - Full format: host:port:privKeyFile:pubKeyFile:receiverPubKeyFile
     */
    public boolean handleSendTransaction(String dataFile, String destination) {
        if (destination == null || destination.isEmpty()) {
            System.err.println("handleSendTransaction: destination is empty");
            return false;
        }

        String serverName = DatabaseOperations.getServerName();
        
        // Read and parse transaction JSON
        long id = generatePositiveId();
        JsonNode root = null;
        String seller = null;
        String buyer = null;
        
        try {
            byte[] raw = Files.readAllBytes(Paths.get(dataFile));
            String content = new String(raw);
            root = tryParseJson(content);
            
            if (root == null || !root.has("seller") || !root.has("buyer") || !root.has("product")) {
                System.err.println("handleSendTransaction: Invalid JSON - missing required fields (seller, buyer, product)");
                return false;
            }
            
            // Extract transaction fields
            id = root.has("id") ? root.get("id").asLong() : generatePositiveId();
            long timestamp = root.has("timestamp") ? root.get("timestamp").asLong() : System.currentTimeMillis();
            seller = root.get("seller").asText();
            buyer = root.get("buyer").asText();
            String product = root.get("product").asText();
            long units = root.has("units") ? root.get("units").asLong() : 0L;
            long amount = root.has("amount") ? root.get("amount").asLong() : 0L;
            
            // VALIDATION: Confirm server is buyer or seller
            if (!serverName.equals(seller) && !serverName.equals(buyer)) {
                System.err.println("handleSendTransaction: Invalid Transaction - server '" + serverName + 
                    "' is neither seller '" + seller + "' nor buyer '" + buyer + "'");
                return false;
            }
            
            System.out.println("Transaction validated: server is " + 
                (serverName.equals(seller) ? "seller" : "buyer"));
            
            // Store transaction in database
            try {
                DatabaseOperations.insertTransaction(id, timestamp, seller, buyer, product, units, amount);
                System.out.println("Stored transaction id=" + id + " in database");
            } catch (SQLException sqe) {
                System.err.println("Failed to store transaction: " + sqe.getMessage());
                return false;
            }
            
            // Check for required shares (example: need at least 1 share from each party)
            boolean sellerHasShares = DatabaseOperations.checkShares(id, "seller", 1);
            boolean buyerHasShares = DatabaseOperations.checkShares(id, "buyer", 1);
            
            if (!sellerHasShares || !buyerHasShares) {
                System.out.println("Shares missing for transaction " + id + 
                    " (seller:" + sellerHasShares + ", buyer:" + buyerHasShares + ")");
                
                // Determine which party to forward to for share generation
                String otherParty = serverName.equals(seller) ? buyer : seller;
                System.out.println("Forwarding transaction to " + otherParty + " for share generation");
                
                // Resolve destination info from database
                DatabaseOperations.DestinationInfo destInfo = DatabaseOperations.getDestinationInfo(otherParty);
                if (destInfo == null) {
                    System.err.println("Cannot resolve destination info for: " + otherParty);
                    return false;
                }
                
                // Record share propagation
                DatabaseOperations.storeSharePropagation(id, otherParty, serverName);
                
                // Build request with resolved info (need to determine key files)
                // For now, using placeholder key files - should be configured
                String privKeyFile = "keys/" + serverName.toLowerCase().replace(" ", "-") + "-private.key";
                String pubKeyFile = "keys/" + serverName.toLowerCase().replace(" ", "-") + "-public.key";
                
                Request req = new Request(
                    destInfo.ip, 
                    destInfo.port, 
                    privKeyFile, 
                    pubKeyFile, 
                    destInfo.publicKey,
                    dataFile, 
                    2 // Type 2 = share request
                );
                enqueueRequest(req);
                System.out.println("Enqueued share request to " + otherParty);
            }
            
        } catch (IOException ioe) {
            System.err.println("handleSendTransaction: failed to read dataFile: " + ioe.getMessage());
            return false;
        } catch (SQLException sqe) {
            System.err.println("handleSendTransaction: database error: " + sqe.getMessage());
            return false;
        }
        
        // Resolve destination for actual transaction sending
        String host;
        int port;
        String privKeyFile;
        String pubKeyFile;
        String receiverPubKeyFile;
        
        // Check if destination is a company name or full format
        if (destination.contains(":")) {
            // Full format: host:port:privKeyFile:pubKeyFile:receiverPubKeyFile
            String[] parts = destination.split(":", 5);
            if (parts.length < 5) {
                System.err.println("handleSendTransaction: destination must be host:port:privKeyFile:pubKeyFile:receiverPubKeyFile");
                return false;
            }
            host = parts[0];
            try {
                port = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                System.err.println("handleSendTransaction: invalid port: " + parts[1]);
                return false;
            }
            privKeyFile = parts[2];
            pubKeyFile = parts[3];
            receiverPubKeyFile = parts[4];
        } else {
            // Company name - resolve from database
            try {
                DatabaseOperations.DestinationInfo destInfo = DatabaseOperations.getDestinationInfo(destination);
                if (destInfo == null) {
                    System.err.println("handleSendTransaction: destination company not found: " + destination);
                    return false;
                }
                host = destInfo.ip;
                port = destInfo.port;
                receiverPubKeyFile = destInfo.publicKey;
                
                // Use server's own keys
                String srvName = DatabaseOperations.getServerName();
                privKeyFile = "keys/" + srvName.toLowerCase().replace(" ", "-") + "-private.key";
                pubKeyFile = "keys/" + srvName.toLowerCase().replace(" ", "-") + "-public.key";
                
                System.out.println("Resolved destination: " + destination + " -> " + host + ":" + port);
            } catch (SQLException sqe) {
                System.err.println("handleSendTransaction: failed to resolve destination: " + sqe.getMessage());
                return false;
            }
        }
        
        // Build the Request and enqueue it
        Request req = new Request(host, port, privKeyFile, pubKeyFile, receiverPubKeyFile, dataFile, 1);
        enqueueRequest(req);
        return true;
    }

    /**
     * Enqueue a Request and notify the sender manager via sendLock.
     */
    public void handleTransactionRequest(Request req) {
        if (req == null) return;
        enqueueRequest(req);
    }

    /**
     * Enqueue a share Request and notify the sender manager.
     */
    public void handleShareRequest(Request req) {
        if (req == null) return;
        enqueueRequest(req);
    }

    /**
     * Process a received (decrypted) transaction payload.
     * Expects payload either as JSON with transaction fields, or as plain text.
     *
     * Example JSON:
     * {
     *   "id": 123,
     *   "timestamp": 1610000000000,
     *   "seller": "Alice",
     *   "buyer": "Bob",
     *   "product": "Widget",
     *   "units": 10,
     *   "amount": 1000
     * }
     *
     * If JSON parsing fails the method will attempt a fallback behavior (log / store placeholder).
     */
    public void handleReceiveTransaction(byte[] decryptedPayload) {
        if (decryptedPayload == null) {
            System.err.println("handleReceiveTransaction: null payload");
            return;
        }
        String payloadText = new String(decryptedPayload);

        JsonNode root = tryParseJson(payloadText);
        if (root != null && (root.has("seller") || root.has("buyer") || root.has("product"))) {
            long parsedId = root.has("id") ? root.get("id").asLong() : generatePositiveId();
            long timestamp = root.has("timestamp") ? root.get("timestamp").asLong() : System.currentTimeMillis();
            String seller = root.has("seller") ? root.get("seller").asText() : "unknown";
            String buyer = root.has("buyer") ? root.get("buyer").asText() : "unknown";
            String product = root.has("product") ? root.get("product").asText() : payloadText;
            long units = root.has("units") ? root.get("units").asLong() : 0L;
            long amount = root.has("amount") ? root.get("amount").asLong() : 0L;

            try {
                DatabaseOperations.insertTransaction(parsedId, timestamp, seller, buyer, product, units, amount);
                System.out.println("handleReceiveTransaction: stored transaction id=" + parsedId);
            } catch (SQLException e) {
                System.err.println("handleReceiveTransaction: DB insert failed: " + e.getMessage());
            }
        } else {
            // Fallback: store a placeholder transaction with the payload as 'product' content
            long id = generatePositiveId();
            long timestamp = System.currentTimeMillis();
            try {
                DatabaseOperations.insertTransaction(id, timestamp, "unknown", "unknown", payloadText, 0L, 0L);
                System.out.println("handleReceiveTransaction: stored fallback transaction id=" + id);
            } catch (SQLException e) {
                System.err.println("handleReceiveTransaction: fallback DB insert failed: " + e.getMessage());
            }
        }
    }

    /**
     * Process a received (decrypted) share payload.
     * Expects JSON like:
     * {
     *   "transactionId": 123,
     *   "share": "some-share-data",
     *   "sharedBy": "seller"
     * }
     *
     * If JSON parsing fails we attempt a lenient fallback (log only).
     */
    public void handleReceiveShare(byte[] decryptedPayload) {
        if (decryptedPayload == null) {
            System.err.println("handleReceiveShare: null payload");
            return;
        }
        String payloadText = new String(decryptedPayload);

        JsonNode root = tryParseJson(payloadText);
        if (root != null && root.has("transactionId") && root.has("share")) {
            long transactionId = root.get("transactionId").asLong();
            String share = root.get("share").asText();
            String sharedBy = root.has("sharedBy") ? root.get("sharedBy").asText() : "seller";
            try {
                DatabaseOperations.addShare(transactionId, share, sharedBy);
                System.out.println("handleReceiveShare: added share to transaction id=" + transactionId);
            } catch (SQLException e) {
                System.err.println("handleReceiveShare: DB addShare failed: " + e.getMessage());
            }
        } else {
            // If not JSON or missing fields, attempt to parse a simple "transactionId|share|sharedBy" format
            String[] parts = payloadText.split("\\|", 3);
            if (parts.length >= 2) {
                try {
                    long transactionId = Long.parseLong(parts[0]);
                    String share = parts[1];
                    String sharedBy = parts.length == 3 ? parts[2] : "seller";
                    DatabaseOperations.addShare(transactionId, share, sharedBy);
                    System.out.println("handleReceiveShare: added share to transaction id=" + transactionId + " (fallback format)");
                } catch (Exception e) {
                    System.err.println("handleReceiveShare: fallback parse failed: " + e.getMessage());
                }
            } else {
                System.err.println("handleReceiveShare: payload not JSON and no fallback format matched. payload=" + payloadText);
            }
        }
    }

    // -------------------------
    // Helper methods
    // -------------------------

    /**
     * Enqueue and notify sender manager.
     */
    private void enqueueRequest(Request req) {
        try {
            sendQueue.put(req); // blocks only if queue bounded and full; LinkedBlockingQueue default is unbounded
            // Notify the senderManager waiting on sendLock
            synchronized (sendLock) {
                sendLock.notify();
            }
            System.out.println("Enqueued request for host=" + req.getHost() + ":" + req.getPort() + " type=" + req.getType());
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            System.err.println("enqueueRequest interrupted: " + ie.getMessage());
        }
    }

    /**
     * Try parse JSON and return JsonNode, or null if parsing fails.
     */
    private JsonNode tryParseJson(String text) {
        if (text == null || text.isEmpty()) return null;
        try {
            return objectMapper.readTree(text);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Generate a positive id using ThreadLocalRandom.
     */
    private long generatePositiveId() {
        long v = ThreadLocalRandom.current().nextLong(Long.MAX_VALUE);
        return v == 0 ? 1 : v;
    }
}
