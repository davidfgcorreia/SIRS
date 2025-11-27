
package com.chainofproduct.client;

import java.util.concurrent.BlockingQueue;

import com.chainofproduct.utils.Request;

public class ClientOperations {
    private final BlockingQueue<Request> sendQueue;
    private final Object sendLock;
    private final String clientName;
    private final String privKeyFile;
    private final String pubKeyFile;
    private final String serverPubKeyFile;
    private final String serverHost;
    private final int serverPort;

    public ClientOperations(BlockingQueue<Request> sendQueue, Object sendLock, String clientName) {
        this.sendQueue = sendQueue;
        this.sendLock = sendLock;
        this.clientName = clientName;

        //demo keys location convention

        this.privKeyFile = "keys/" + clientName.toLowerCase().replace(" ", "-") + "-private.key";
        this.pubKeyFile = "keys/" + clientName.toLowerCase().replace(" ", "-") + "-public.key";
        this.serverPubKeyFile = "keys/server-public.key";
        this.serverHost = "localhost";
        this.serverPort = 50051;

    }

    // Enqueue a transaction send request (Type 1)
    public void sendtrsaction(String dataFile, String destination) {
        String payload = "{request_type:"+ "transaction" +", destination: " + destination + "}" + dataFile;

        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.privKeyFile,
            this.pubKeyFile,
            this.serverPubKeyFile,
            payload
        );
        enqueueRequest(req);
        System.out.println("Enqueued transaction send request for " + destination);
    }

    // Enqueue a getById request (Type 3)
    public void gettransactionById(long id) {
        String payload = "{request_type:"+ "getById" + ", servername: " + this.clientName +  ", trasaction_id: " + id + "}";
        Request req = new Request(
           this.serverHost,
            this.serverPort,
            this.privKeyFile,
            this.pubKeyFile,
            this.serverPubKeyFile,
            payload
        );
        enqueueRequest(req);
        System.out.println("Enqueued getById request for id=" + id);
    }

    // Enqueue a getAll request (Type 4)
    public void getAll() {
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.privKeyFile,
            this.pubKeyFile,
            this.serverPubKeyFile,
            "{request_type:getAll, servername: " + this.clientName + "}"
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
            this.privKeyFile,
            this.pubKeyFile,
            this.serverPubKeyFile,
            payload
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
            this.privKeyFile,
            this.pubKeyFile,
            this.serverPubKeyFile,
            payload
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
            this.privKeyFile,
            this.pubKeyFile,
            this.serverPubKeyFile,
            payload
        );
        enqueueRequest(req);
        System.out.println("Enqueued getRecentTransactions request since timestamp=" + sinceTimestamp);
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
}
