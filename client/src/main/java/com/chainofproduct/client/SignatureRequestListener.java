package com.chainofproduct.client;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.net.Socket;

/**
 * Listens for incoming signature requests from other clients and responds using ClientOperations.
 */
public class SignatureRequestListener implements Runnable {
    private final ClientOperations clientOps;
    private final int port;
    private volatile boolean running = true;
    private Thread listenerThread;

    public SignatureRequestListener(ClientOperations clientOps, int port) {
        this.clientOps = clientOps;
        this.port = port;
    }

    public void start() {
        listenerThread = new Thread(() -> this.run(), "SignatureRequestListener");
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    public void stop() {
        running = false;
        if (listenerThread != null) {
            listenerThread.interrupt();
        }
    }

    public void join(long timeout) throws InterruptedException {
        if (listenerThread != null) {
            listenerThread.join(timeout);
        }
    }

    @Override
    public void run() {
        try {
            // Load keystore and truststore using ClientOperations logic
            String clientName = clientOps.getClass().getDeclaredField("clientName").get(clientOps).toString();
            int clientNum = (int) clientOps.getClass().getDeclaredField("clientNum").get(clientOps);
            String keystorePath = "client" + clientNum + "-keystore.p12";
            String truststorePath = "keys/client-truststore-pubkeys.p12";
            String password = "changeit";

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
                keyStore.load(fis, password.toCharArray());
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password.toCharArray());

            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(truststorePath)) {
                trustStore.load(fis, password.toCharArray());
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
            try (SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port)) {
                serverSocket.setNeedClientAuth(true); // Require client certificate
                System.out.println("[SignatureRequestListener] TLS listening on port " + port);
                while (running) {
                    try {
                        Socket socket = serverSocket.accept();
                        handleClient(socket);
                    } catch (Exception e) {
                        if (running) {
                            System.err.println("[SignatureRequestListener] Error: " + e.getMessage());
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[SignatureRequestListener] Failed to start TLS: " + e.getMessage());
        }
    }

    private void handleClient(Socket socket) {
        try {
            com.chainofproduct.utils.ApiCalls.handleClient(socket, request -> clientOps.handleSignatureRequest(request));
        } catch (Exception e) {
            System.err.println("[SignatureRequestListener] Client error: " + e.getMessage());
        }
    }
}
