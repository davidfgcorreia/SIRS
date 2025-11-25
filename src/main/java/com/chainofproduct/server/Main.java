package com.chainofproduct.server;

import com.chainofproduct.db.DatabaseOperations;
import com.chainofproduct.utils.CryptoUtils;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class Main {
    public static void main(String[] args) throws Exception {
        // SET SERVER IDENTITY - Configure which company this server represents
        // This MUST match one of the companies in destination_ips table
        // Options: "Lays Chips", "Stealing Corporation", "Ching Chong Extractions"
        String serverIdentity = System.getProperty("server.name", "Lays Chips");
        DatabaseOperations.setServerName(serverIdentity);
        System.out.println("Server identity set to: " + serverIdentity);
        
        // Initialize CryptoUtils to ensure replay-protection timer and nonce map are started
        try {
            CryptoUtils.generateNonce();
            System.out.println("CryptoUtils initialized (replay protection active).");
        } catch (Throwable t) {
            System.err.println("Warning: failed to initialize CryptoUtils: " + t.getMessage());
        }
        // Shared queue and lock for sender requests
        BlockingQueue<Request> sendQueue = new LinkedBlockingQueue<>();
        Object sendLock = new Object();

        // Start TLS receiver thread (copied from ApiServer)
        final int TLS_PORT = 8443;
        final String KEYSTORE = "server-keystore.jks";
        final String KEYSTORE_PASSWORD = "changeit";

        
        Thread receiverThread = new Thread(() -> {
            System.setProperty("javax.net.ssl.keyStore", KEYSTORE);
            System.setProperty("javax.net.ssl.keyStorePassword", KEYSTORE_PASSWORD);
            javax.net.ssl.SSLServerSocketFactory ssf = (javax.net.ssl.SSLServerSocketFactory) javax.net.ssl.SSLServerSocketFactory.getDefault();
            try (javax.net.ssl.SSLServerSocket serverSocket = (javax.net.ssl.SSLServerSocket) ssf.createServerSocket(TLS_PORT)) {
                System.out.println("API Server listening on port " + TLS_PORT + " (TLS)");
                java.util.concurrent.ExecutorService receiverPool = java.util.concurrent.Executors.newFixedThreadPool(10);
                while (true) {
                    final javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) serverSocket.accept();
                    receiverPool.submit(() -> {
                        try {
                            ApiServer.handleClient(socket);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        receiverThread.setDaemon(true);
        receiverThread.start();

        // Start gRPC server
        int grpcPort = 50051; // Default gRPC port
        Server grpcServer = ServerBuilder.forPort(grpcPort)
                .addService(new ServerServiceImpl(sendQueue, sendLock))
                .build()
                .start();
        System.out.println("gRPC API server started, listening on port " + grpcPort);

        // Start the sender manager thread (similar to ApiServer)
        Thread senderManager = new Thread(() -> {
            while (true) {
                try {
                    final Request req;
                    synchronized (sendLock) {
                        while (sendQueue.isEmpty()) {
                            try {
                                sendLock.wait();
                            } catch (InterruptedException e) {
                                // Allow thread to exit on interrupt
                                return;
                            }
                        }
                        req = sendQueue.poll();
                    }
                    if (req != null) {
                        // Type 1 = transaction, Type 2 = share
                        Runnable sendTask = () -> {
                            try {
                                if (req.getType() == 1 || req.getType() == 2) {
                                    // Updated: pass senderPrivKeyFile, senderPubKeyFile, receiverPubKeyFile, dataFile
                                    ApiServer.actAsSender(
                                        req.getHost(),
                                        req.getPort(),
                                        req.getPrivKeyFile(),
                                        req.getPubKeyFile(),
                                        req.getReceiverPubKeyFile(),
                                        req.getDataFile()
                                    );
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        };
                        // Use a thread pool if needed, for now just run in new thread
                        new Thread(sendTask).start();
                    }
                } catch (Exception e) {
                    // Allow thread to exit on interrupt or handle other exceptions
                    break;
                }
            }
        });
        senderManager.setDaemon(true);
        senderManager.start();

        // Add shutdown hook for clean exit
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down gRPC server...");
            grpcServer.shutdown();
        }));

        // Keep main thread alive
        grpcServer.awaitTermination();
    }
}