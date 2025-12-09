package com.chainofproduct.server;

import com.chainofproduct.utils.ApiCalls;
import com.chainofproduct.utils.CryptoUtils;
import com.chainofproduct.utils.KeyTransmission;


public class Main {
    
    // Server metrics
    private static long requestsProcessed = 0;
    private static long requestsFailed = 0;
    private static long startTime = System.currentTimeMillis();
    
    // Rate limiting (simple token bucket)
    private static final int MAX_REQUESTS_PER_MINUTE = 100;
    private static final java.util.Map<String, java.util.concurrent.atomic.AtomicInteger> requestCounts = 
        new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.Map<String, Long> lastResetTime = 
        new java.util.concurrent.ConcurrentHashMap<>();
    
    public static void main(String[] args) throws Exception {
        
        String serverName = "server";
        System.out.println("Generating keys...");
        com.chainofproduct.utils.Cerificates.main(new String[]{serverName});


        // Start EC keypair and key exchange listener using KeyTransmission (utils package)
        KeyTransmission keyTransmission = new KeyTransmission();
        Thread ecKeyExchangeThread = new Thread(() -> {
            try {
                // Use serverName as storePrefix, and resolve port for key exchange
                System.out.println("Starting EC key exchange listener...");
                com.chainofproduct.utils.ResolveDestinations.DestinationInfo destInfo = 
                    com.chainofproduct.utils.ResolveDestinations.resolve(serverName);
                int keyExchangePort = destInfo.certPort;
                keyTransmission.ensureECKeyAndStartListener(serverName, keyExchangePort);
                System.out.println("EC key exchange listener started on port " + keyExchangePort);
            } catch (Exception e) {
                System.err.println("Failed to start EC key exchange listener: " + e.getMessage());
                e.printStackTrace();
            }
        }, "ECKeyExchangeListener");
        ecKeyExchangeThread.setDaemon(true);
        ecKeyExchangeThread.start();
        
        // Initialize CryptoUtils to ensure replay-protection timer and nonce map are started
        try {
            System.out.println("Initializing CryptoUtils...");
            CryptoUtils.generateNonce();
            System.out.println("CryptoUtils initialized (replay protection active)");
        } catch (Throwable t) {
            System.err.println("Failed to initialize CryptoUtils: " + t.getMessage());
        }

        // Exchange certificates with database if needed
        try {
            System.out.println("Checking certificate exchange with database...");
            // Load database connection info from config
            com.chainofproduct.utils.ResolveDestinations.DestinationInfo dbInfo = 
            com.chainofproduct.utils.ResolveDestinations.resolve("db");
            
            com.chainofproduct.utils.Cerificates.verifyCertificaAndObtain(
                serverName,     // myEntityName: "server"
                "db",           // receiverName: database
                dbInfo.ip,      // receiverIp
                dbInfo.certPort // receiverPort (certificate exchange port)
            );
            System.out.println("Certificate exchange with database completed");
        } catch (Exception e) {
            System.err.println("Certificate exchange with database failed: " + e.getMessage());
            e.printStackTrace();
        }

        // Create ServerOperations to handle requests
        final ServerOperations serverOps = new ServerOperations();


        // Start TLS receiver thread - this is the ONLY communication channel now
        // Load TLS port from config
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
        
        // Setup TLS/SSL context for server
        String keystorePath = getEnvOrDefault("SERVER_KEYSTORE_PATH", "server-keystore.p12");
        String truststorePath = getEnvOrDefault("SERVER_TRUSTSTORE_PATH", "server-truststore.p12");
        String password = getEnvOrDefault("SERVER_KEYSTORE_PASSWORD", "changeit");
        
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
        
        // Create receiver pool outside try block so it can be shut down in finally
        int poolSize = 10;  // default
        try {
            String poolSizeStr = getEnvOrDefault("SERVER_THREAD_POOL_SIZE", "10");
            poolSize = Integer.parseInt(poolSizeStr);
            System.out.println("[CONFIG] Receiver pool size: " + poolSize);
        } catch (NumberFormatException e) {
            System.err.println("[WARN] Invalid thread pool size, using default: 10");
        }
        java.util.concurrent.ExecutorService receiverPool = java.util.concurrent.Executors.newFixedThreadPool(poolSize);
        
        try {
            System.out.println("=".repeat(60) + "\n");
            
            // Metrics reporting thread
            Thread metricsThread = new Thread(() -> {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        Thread.sleep(60000); // Every 60 seconds
                        System.out.println("\n[METRICS] " + getMetrics() + "\n");
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
                if (!checkRateLimit(clientAddress)) {
                    System.err.println("[WARN] Rate limit exceeded for " + clientAddress);
                    try {
                        socket.close();
                    } catch (Exception e) {
                        // Ignore
                    }
                    incrementErrors();
                    continue;
                }
                
                receiverPool.submit(() -> {
                    long startTime = System.currentTimeMillis();
                    try {
                        // Set socket timeout to prevent hanging connections
                        socket.setSoTimeout(30000); // 30 second timeout
                        
                        // Use custom executor to process requests and return responses
                        ApiCalls.handleClient(socket, (byte[] request) -> {
                            byte[] response = serverOps.processRequest(request);
                            incrementRequests();
                            long elapsed = System.currentTimeMillis() - startTime;
                            System.out.println("[INFO] Request processed in " + elapsed + "ms from " + clientAddress);
                            return response;
                        });
                    } catch (java.net.SocketTimeoutException e) {
                        incrementErrors();
                        System.err.println("[ERROR] Timeout for client " + clientAddress);
                    } catch (Exception e) {
                        incrementErrors();
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
     * Gets configuration value from environment variable or returns default.
     */
    private static String getEnvOrDefault(String envVar, String defaultValue) {
        String value = System.getenv(envVar);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
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
    
    /**
     * Check rate limit for client IP (simple token bucket).
     * Returns true if request is allowed, false if rate limit exceeded.
     */
    private static boolean checkRateLimit(String clientIp) {
        long now = System.currentTimeMillis();
        
        // Reset counter if minute has passed
        Long lastReset = lastResetTime.get(clientIp);
        if (lastReset == null || (now - lastReset) > 60000) {
            lastResetTime.put(clientIp, now);
            requestCounts.put(clientIp, new java.util.concurrent.atomic.AtomicInteger(0));
        }
        
        // Check and increment counter
        java.util.concurrent.atomic.AtomicInteger counter = requestCounts.get(clientIp);
        if (counter == null) {
            counter = new java.util.concurrent.atomic.AtomicInteger(0);
            requestCounts.put(clientIp, counter);
        }
        
        int count = counter.incrementAndGet();
        return count <= MAX_REQUESTS_PER_MINUTE;
    }
}