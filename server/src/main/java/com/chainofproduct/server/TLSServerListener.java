package com.chainofproduct.server;
import com.chainofproduct.utils.KeyTransmission;



import com.chainofproduct.utils.ApiCalls;

public class TLSServerListener {


        // Server metrics
    private static long requestsProcessed = 0;
    private static long requestsFailed = 0;
    private static long startTime = System.currentTimeMillis();
    

    /**
     * Start the TLS listener thread, accepting connections and dispatching to the receiver pool.
     * Handles metrics, rate limiting, and graceful shutdown.
     */
    public static void startListener(String serverName, ServerOperations serverOps, KeyTransmission keyTransmission) throws Exception {
        int TLS_PORT = 8443;  // default
        try {
            com.chainofproduct.utils.ResolveDestinations.DestinationInfo serverInfo =
                com.chainofproduct.utils.ResolveDestinations.resolve(serverName);
            TLS_PORT = serverInfo.port;
            System.out.println("Server TLS port loaded from config: " + TLS_PORT);
        } catch (Exception e) {
            System.err.println("Warning: Failed to load server port from config, using default: " + TLS_PORT);
        }
        final int SERVER_TLS_PORT = TLS_PORT;

        String keystorePath = Main.getEnvOrDefault("SERVER_KEYSTORE_PATH", "server-keystore.p12");
        String truststorePath = Main.getEnvOrDefault("SERVER_TRUSTSTORE_PATH", "server-truststore.p12");
        String password = Main.getEnvOrDefault("SERVER_KEYSTORE_PASSWORD", "changeit");

        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
            keyStore.load(fis, password.toCharArray());
        }

        java.security.KeyStore trustStore = java.security.KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(truststorePath)) {
            trustStore.load(fis, password.toCharArray());
        }

        javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, password.toCharArray());

        javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);

        javax.net.ssl.SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());

        javax.net.ssl.SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        javax.net.ssl.SSLServerSocket serverSocket = (javax.net.ssl.SSLServerSocket) factory.createServerSocket(SERVER_TLS_PORT);
        serverSocket.setNeedClientAuth(true); // Require client certificates

        int poolSize = 10;  // default
        try {
            String poolSizeStr = Main.getEnvOrDefault("SERVER_THREAD_POOL_SIZE", "10");
            poolSize = Integer.parseInt(poolSizeStr);
            System.out.println("[CONFIG] Receiver pool size: " + poolSize);
        } catch (NumberFormatException e) {
            System.err.println("[WARN] Invalid thread pool size, using default: 10");
        }
        java.util.concurrent.ExecutorService receiverPool = java.util.concurrent.Executors.newFixedThreadPool(poolSize);

        // Rate limiting (simple token bucket)
        final int MAX_REQUESTS_PER_MINUTE = 100;
        final java.util.Map<String, java.util.concurrent.atomic.AtomicInteger> requestCounts = new java.util.concurrent.ConcurrentHashMap<>();
        final java.util.Map<String, Long> lastResetTime = new java.util.concurrent.ConcurrentHashMap<>();

        try {
            System.out.println("=".repeat(60) + "\n");

            // Metrics reporting thread
            Thread metricsThread = new Thread(() -> {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        Thread.sleep(60000); // Every 60 seconds
                        System.out.println("\n[METRICS] " + TLSServerListener.getMetrics() + "\n");
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            });
            metricsThread.setDaemon(true);
            metricsThread.start();

            while (true) {
                final java.net.Socket socket = serverSocket.accept();
                final String clientAddress = socket.getInetAddress().getHostAddress();
                System.out.println("[INFO] New connection from: " + clientAddress);

                // Rate limiting check
                if (!checkRateLimit(clientAddress, requestCounts, lastResetTime, MAX_REQUESTS_PER_MINUTE)) {
                    System.err.println("[WARN] Rate limit exceeded for " + clientAddress);
                    try {
                        socket.close();
                    } catch (Exception e) {
                        // Ignore
                    }
                    TLSServerListener.incrementErrors();
                    continue;
                }

                receiverPool.submit(() -> {
                    long startTime = System.currentTimeMillis();
                    try {
                        // Set socket timeout to prevent hanging connections
                        socket.setSoTimeout(30000); // 30 second timeout

                        // Use custom executor to process requests and return responses
                        ApiCalls.handleClient(socket, (byte[] request) -> {
                            String certAlias = null;
                            try {
                                if (socket instanceof javax.net.ssl.SSLSocket) {
                                    javax.net.ssl.SSLSocket sslSocket = (javax.net.ssl.SSLSocket) socket;
                                    javax.net.ssl.SSLSession session = sslSocket.getSession();
                                    java.security.cert.Certificate[] certs = session.getPeerCertificates();
                                    if (certs != null && certs.length > 0) {
                                        java.security.cert.X509Certificate x509 = (java.security.cert.X509Certificate) certs[0];
                                        certAlias = x509.getSubjectX500Principal().getName();
                                    }
                                }
                            } catch (Exception e) {
                                System.err.println("[WARN] Could not extract client certificate alias: " + e.getMessage());
                            }
                            byte[] response = serverOps.processRequest(request, certAlias);
                            TLSServerListener.incrementRequests();
                            long elapsed = System.currentTimeMillis() - startTime;
                            System.out.println("[INFO] Request processed in " + elapsed + "ms from " + clientAddress + (certAlias != null ? (" (cert alias: " + certAlias + ")") : ""));
                            return response;
                        });
                    } catch (java.net.SocketTimeoutException e) {
                        TLSServerListener.incrementErrors();
                        System.err.println("[ERROR] Timeout for client " + clientAddress);
                    } catch (Exception e) {
                        TLSServerListener.incrementErrors();
                        System.err.println("[ERROR] Error handling client " + clientAddress + ": " + e.getMessage());
                        e.printStackTrace();
                    }
                });
            }
        } finally {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("Server shutdown initiated");
            System.out.println("=".repeat(60));

            // Shutdown key exchange listener
            System.out.println("Closing key exchange listener...");
            keyTransmission.closeKeyExchangeListener();
            System.out.println("Key exchange listener closed");

            // Shutdown receiver pool gracefully
            System.out.println("Shutting down receiver pool...");
            receiverPool.shutdown();
            try {
                if (!receiverPool.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS)) {
                    System.err.println("Receiver pool did not terminate in time, forcing shutdown...");
                    receiverPool.shutdownNow();
                } else {
                    System.out.println("Receiver pool terminated gracefully");
                }
            } catch (InterruptedException e) {
                System.err.println("Interrupted during shutdown, forcing shutdown...");
                receiverPool.shutdownNow();
                Thread.currentThread().interrupt();
            }

            System.out.println("Closing server socket...");
            serverSocket.close();
            System.out.println("Server socket closed");
        }
    }

    /**
     * Check rate limit for client IP (simple token bucket).
     */
    private static boolean checkRateLimit(String clientIp, java.util.Map<String, java.util.concurrent.atomic.AtomicInteger> requestCounts, java.util.Map<String, Long> lastResetTime, int maxRequestsPerMinute) {
        long now = System.currentTimeMillis();
        Long lastReset = lastResetTime.get(clientIp);
        if (lastReset == null || (now - lastReset) > 60000) {
            lastResetTime.put(clientIp, now);
            requestCounts.put(clientIp, new java.util.concurrent.atomic.AtomicInteger(0));
        }
        java.util.concurrent.atomic.AtomicInteger counter = requestCounts.get(clientIp);
        if (counter == null) {
            counter = new java.util.concurrent.atomic.AtomicInteger(0);
            requestCounts.put(clientIp, counter);
        }
        int count = counter.incrementAndGet();
        return count <= maxRequestsPerMinute;
    }

        /**
     * Increments request counter (thread-safe).
     */
    public static synchronized void incrementRequests() {
        requestsProcessed++;
    }
    
    /**
     * Increments error counter (thread-safe).
     */
    public static synchronized void incrementErrors() {
        requestsFailed++;
    }
    
    /**
     * Returns server metrics as formatted string.
     */
    public static synchronized String getMetrics() {
        long uptime = (System.currentTimeMillis() - startTime) / 1000;
        return String.format("Uptime: %ds | Requests: %d | Errors: %d | Success Rate: %.2f%%",
            uptime, requestsProcessed, requestsFailed,
            requestsProcessed > 0 ? (100.0 * (requestsProcessed - requestsFailed) / requestsProcessed) : 0.0);
    }


}

