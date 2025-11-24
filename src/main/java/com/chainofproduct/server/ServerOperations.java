package com.chainofproduct.server;
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
     * Resolve the destination, create a DB transaction record (if possible),
     * enqueue a Request for the sender manager, and notify the manager.
     *
     * Destination format expected (simple): host:port:privKeyFile:receiverPubKeyFile
     *
     * Returns true if the request was accepted and queued (or DB insert succeeded),
     * false otherwise.
     */
    public boolean handleSendTransaction(String dataFile, String destination) {
        if (destination == null || destination.isEmpty()) {
            System.err.println("handleSendTransaction: destination is empty");
            return false;
        }

        // Try to parse destination
        String[] parts = destination.split(":", 4);
        if (parts.length < 4) {
            System.err.println("handleSendTransaction: destination must be host:port:privKeyFile:receiverPubKeyFile");
            return false;
        }
        String host = parts[0];
        int port;
        try {
            port = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            System.err.println("handleSendTransaction: invalid port: " + parts[1]);
            return false;
        }
        String privKeyFile = parts[2];
        String receiverPubKeyFile = parts[3];

        // Attempt to read dataFile and, if JSON with transaction fields, insert into DB
        long id = generatePositiveId();
        try {
            byte[] raw = Files.readAllBytes(Paths.get(dataFile));
            String content = new String(raw);

            // Try parse JSON as a transaction record
            JsonNode root = tryParseJson(content);
            if (root != null && root.has("seller") && root.has("buyer") && root.has("product")) {
                // Extract fields (use defaults if missing)
                long parsedId = root.has("id") ? root.get("id").asLong() : id;
                long timestamp = root.has("timestamp") ? root.get("timestamp").asLong() : System.currentTimeMillis();
                String seller = root.has("seller") ? root.get("seller").asText() : "unknown";
                String buyer = root.has("buyer") ? root.get("buyer").asText() : destination;
                String product = root.has("product") ? root.get("product").asText() : dataFile;
                long units = root.has("units") ? root.get("units").asLong() : 0L;
                long amount = root.has("amount") ? root.get("amount").asLong() : 0L;

                // Insert into DB (ON CONFLICT DO NOTHING in your SQL will protect duplicates)
                try {
                    DatabaseOperations.insertTransaction(parsedId, timestamp, seller, buyer, product, units, amount);
                    id = parsedId; // use parsed id if present
                    System.out.println("Inserted transaction id=" + parsedId + " into DB before sending.");
                } catch (SQLException sqe) {
                    System.err.println("DB insert failed (continuing): " + sqe.getMessage());
                }

            } else {
                // Not JSON or missing expected fields: create a placeholder DB record
                long timestamp = System.currentTimeMillis();
                String seller = "unknown";
                String buyer = destination;
                String product = dataFile; // store filename as product if we don't have details
                try {
                    DatabaseOperations.insertTransaction(id, timestamp, seller, buyer, product, 0L, 0L);
                    System.out.println("Inserted placeholder transaction id=" + id + " into DB before sending.");
                } catch (SQLException sqe) {
                    System.err.println("DB insert failed for placeholder (continuing): " + sqe.getMessage());
                }
            }
        } catch (IOException ioe) {
            System.err.println("handleSendTransaction: failed to read dataFile '" + dataFile + "': " + ioe.getMessage());
            // We continue and still enqueue the request so sender can attempt sending raw file. Return false would be valid too.
        }

        // Build the Request and enqueue it
        Request req = new Request(host, port, privKeyFile, receiverPubKeyFile, dataFile, 1);
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
