package com.chainofproduct.server;

import com.chainofproduct.db.DatabaseOperations;
import com.chainofproduct.utils.Request;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.concurrent.BlockingQueue;

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
    private final String serverName;

    public ServerOperations(BlockingQueue<Request> sendQueue, Object sendLock) {
        this.sendQueue = sendQueue;
        this.sendLock = sendLock;
        this.serverName = DatabaseOperations.getServerName();
        
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

        boolean sellerFlag = false;
        boolean parterHasTransaction = false;
        DatabaseOperations.DestinationInfo destInfoShare = null;
        String seller ;
        String buyer ;

        String privKeyFile = "keys/" + serverName.toLowerCase().replace(" ", "-") + "-private.key";
        String pubKeyFile = "keys/" + serverName.toLowerCase().replace(" ", "-") + "-public.key";

        if (destination == null || destination.isEmpty()) {
            System.err.println("handleSendTransaction: destination is empty");
            return false;
        }
        
        // Read and parse transaction JSON
        JsonNode root = null;

        
        try {
            byte[] raw = Files.readAllBytes(Paths.get(dataFile));
            String content = new String(raw);
            root = tryParseJson(content);
            
            if (root == null 
                || !root.hasNonNull("id") 
                || !root.hasNonNull("timestamp")
                || !root.hasNonNull("seller") 
                || !root.hasNonNull("buyer") 
                || !root.hasNonNull("product") 
                || !root.hasNonNull("units") 
                || !root.hasNonNull("amount")) {
                System.err.println("handleSendTransaction: Invalid JSON - missing required fields (id, timestamp, seller, buyer, product, units, amount)");
                return false;
            }
            if (!root.get("id").canConvertToLong() || !root.get("timestamp").canConvertToLong()
                || !root.get("units").canConvertToLong() || !root.get("amount").canConvertToLong()) {
                System.err.println("handleSendTransaction: id, timestamp, units, and amount must be numbers");
                return false;
            }
            
            // Extract transaction fields
            long id = root.get("id").asLong();
            long timestamp = root.get("timestamp").asLong();
            seller = root.get("seller").asText();
            buyer = root.get("buyer").asText();
            String product = root.get("product").asText();
            long units = root.get("units").asLong();
            long amount = root.get("amount").asLong();
            
            // VALIDATION: Confirm server is buyer or seller
            if (!serverName.equals(seller) && !serverName.equals(buyer)) {
                System.err.println("handleSendTransaction: Invalid Transaction - server '" + serverName + 
                    "' is neither seller '" + seller + "' nor buyer '" + buyer + "'");
                return false;
            }
            
            System.out.println("Transaction validated: server is " + 
                (serverName.equals(seller) ? "seller" : "buyer"));
            sellerFlag = serverName.equals(seller);
            
            // Store transaction in database
            try {
                DatabaseOperations.insertTransaction(id, timestamp, seller, buyer, product, units, amount);
                System.out.println("Stored transaction id=" + id + " in database");

                // NEW: Check all shares for this transaction id
                try {
                    java.util.List<String> partnerShares = DatabaseOperations.getSharesBySharedBy(id, sellerFlag ? buyer : seller);
                    System.out.println("Shares sent by (" + (sellerFlag ? buyer : seller) + "): " + partnerShares);
                    // Optionally, check if a share was already sent by me (serverName) to buyer or seller
                    java.util.List<String> myShares = DatabaseOperations.getSharesBySharedBy(id, serverName);
                    System.out.println("Shares sent by me (" + serverName + "): " + myShares);
                    // Determine if partner sent me the transaction (true = already sent, false = not sent)
                    parterHasTransaction = partnerShares != null && !partnerShares.isEmpty();
                    System.out.println("Partner sent me transaction? " + parterHasTransaction);
                } catch (SQLException sqe) {
                    System.err.println("Failed to fetch shares for transaction: " + sqe.getMessage());
                }
            } catch (SQLException sqe) {
                System.err.println("Failed to store transaction: " + sqe.getMessage());
                return false;
            }


            // Determine which party to forward to for share generation
                String otherParty = sellerFlag ? seller : buyer;
                System.out.println("Forwarding transaction to " + otherParty + " for share generation");
                
                // Resolve destination info from database
                destInfoShare = DatabaseOperations.getDestinationInfo(otherParty);
                if (destInfoShare == null) {
                    System.err.println("Cannot resolve destination info for: " + otherParty);
                    return false;
                }
            if (!parterHasTransaction) {
                                
                // Record share propagation
                DatabaseOperations.addShare(id, otherParty, serverName);
                
                // Build request with resolved info (need to determine key files)
                // For now, using placeholder key files - should be configured
                //
                
                //send transaction data to other party if they dont have it
                Request reqtr = new Request(
                    destInfoShare.ip, 
                    destInfoShare.port, 
                    privKeyFile, 
                    pubKeyFile, 
                    destInfoShare.publicKey,
                    dataFile, 
                    1 // Type 1 = trasction sahre
                );
                enqueueRequest(reqtr);
                System.out.println("Enqueued share request to " + otherParty);


                //send share to other party
                Request reqstr = new Request(
                    destInfoShare.ip, 
                    destInfoShare.port, 
                    privKeyFile, 
                    pubKeyFile, 
                    destInfoShare.publicKey,
                    serverName + "|" + id + "|" + otherParty, 
                    2 // Type 2 = transaction share
                );
                enqueueRequest(reqstr);
                System.out.println("Enqueued share request to " + otherParty);

            }
            
        } catch (IOException ioe) {
            System.err.println("handleSendTransaction: failed to read dataFile: " + ioe.getMessage());
            return false;
        } catch (SQLException sqe) {
            System.err.println("handleSendTransaction: database error: " + sqe.getMessage());
            return false;
        }
        

        DatabaseOperations.DestinationInfo destInfo= null;    
            try {
                destInfo = DatabaseOperations.getDestinationInfo(destination);
                if (destInfo == null) {
                    System.err.println("handleSendTransaction: destination company not found: " + destination);
                    return false;
                }
                
                System.out.println("Resolved destination: " + destination + " -> " + destInfo.ip + ":" + destInfo.port);
            } catch (SQLException sqe) {
                System.err.println("handleSendTransaction: failed to resolve destination: " + sqe.getMessage());
                return false;
            }
        
        // Build the Request and enqueue it
        Request req = new Request(destInfo.ip, destInfo.port, privKeyFile, pubKeyFile, destInfo.publicKey, dataFile, 1);
        enqueueRequest(req);

        Request reqShare = new Request(destInfoShare.ip, destInfoShare.port, privKeyFile, pubKeyFile, destInfoShare.publicKey, serverName + "|" + destination, 2);
        enqueueRequest(reqShare);

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
            throw new IllegalArgumentException("handleReceiveTransaction: null payload");
        }
        String payloadText = new String(decryptedPayload);

        JsonNode root = tryParseJson(payloadText);
        // Require all fields: id, timestamp, seller, buyer, product, units, amount
        if (root == null
            || !root.hasNonNull("id")
            || !root.hasNonNull("timestamp")
            || !root.hasNonNull("seller")
            || !root.hasNonNull("buyer")
            || !root.hasNonNull("product")
            || !root.hasNonNull("units")
            || !root.hasNonNull("amount")
            || !root.get("id").canConvertToLong()
            || !root.get("timestamp").canConvertToLong()
            || !root.get("units").canConvertToLong()
            || !root.get("amount").canConvertToLong()) {
            throw new IllegalArgumentException("handleReceiveTransaction: payload not JSON or missing required fields. payload=" + payloadText);
        }
        long parsedId = root.get("id").asLong();
        long timestamp = root.get("timestamp").asLong();
        String seller = root.get("seller").asText();
        String buyer = root.get("buyer").asText();
        String product = root.get("product").asText();
        long units = root.get("units").asLong();
        long amount = root.get("amount").asLong();

        try {
            DatabaseOperations.insertTransaction(parsedId, timestamp, seller, buyer, product, units, amount);
            System.out.println("handleReceiveTransaction: stored transaction id=" + parsedId);
        } catch (SQLException e) {
            System.err.println("handleReceiveTransaction: DB insert failed: " + e.getMessage());
        }
    }
    

    /**
     * Process a received (decrypted) share payload.
     * Expects format:
     *   senderName|transactionId|receiverName
     * Example:
     *   Alice|123|Bob
     *
     * The payload must be a single string with sender name, transaction id, and receiver name separated by '|'.
     */
    public void handleReceiveShare(byte[] decryptedPayload) {
        if (decryptedPayload == null) {
            System.err.println("handleReceiveShare: null payload");
            return;
        }
        String payloadText = new String(decryptedPayload);

        // Expect format: senderName|transactionId|receiverName
        String[] parts = payloadText.split("\\|", 3);
        if (parts.length == 3) {
            String senderName = parts[0].trim();
            long transactionId;
            try {
                transactionId = Long.parseLong(parts[1].trim());
            } catch (NumberFormatException e) {
                System.err.println("handleReceiveShare: invalid transactionId in payload: " + payloadText);
                return;
            }
            // receiverName = parts[2].trim(); // Not used in DB
            try {
                DatabaseOperations.addShare(transactionId, payloadText, senderName);
                System.out.println("handleReceiveShare: added share (string format) to transaction id=" + transactionId);
            } catch (SQLException e) {
                System.err.println("handleReceiveShare: DB addShare failed: " + e.getMessage());
            }
        } else {
            System.err.println("handleReceiveShare: payload not in 'sender|id|receiver' format. payload=" + payloadText);
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
                sendLock.notifyAll();
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

}
