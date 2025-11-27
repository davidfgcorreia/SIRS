package com.chainofproduct.utils;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.nio.ByteBuffer;
import java.time.Instant;

public class CryptoUtils {
    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;
    private static final byte VERSION = 1; // Protocol version
    private static final int NONCE_LENGTH = 12; // 96 bits, same as IV for convenience

    // Replay protection: track used nonces and their expiration
    private static final java.util.Map<String, Long> usedNonces = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.Timer nonceCleanupTimer = new java.util.Timer(true);

    static {
        // Schedule periodic cleanup of expired nonces
        nonceCleanupTimer.schedule(new java.util.TimerTask() {
            @Override
            public void run() {
                long now = System.currentTimeMillis();
                usedNonces.entrySet().removeIf(e -> e.getValue() < now);
            }
        }, 60_000, 60_000); // every 1 minute
    }
    
    // Reuse SecureRandom instance for better performance
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    // Clock drift tolerance in milliseconds (for timestamp validation)
    private static final long CLOCK_DRIFT_TOLERANCE = 60 * 1000; // 1 minute

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    
    public static SecretKey generateAESKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(keySize);
        return keyGen.generateKey();
    }
    
    /**
     * Generate HMAC key for user authentication.
     * Each user (buyer/seller) should have their own static HMAC key.
     */
    public static SecretKey generateHMACKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(HMAC_ALGORITHM);
        keyGen.init(256); // 256-bit HMAC key
        return keyGen.generateKey();
    }


    /**
     * Encrypts data with HMAC authentication using user's symmetric key.
     * This is used for transaction data where each party (buyer/seller) encrypts with their own key.
     * Structure: [version][IV][ciphertext][HMAC]
     * 
     * @param data The data to encrypt
     * @param aesKey AES encryption key
     * @param hmacKey HMAC key for the user (buyer or seller)
     * @param userId User identifier (e.g., "buyer" or "seller")
     * @return base64-encoded encrypted data with HMAC
     */
    public static String encryptWithHMAC(byte[] data, SecretKey aesKey, SecretKey hmacKey, String userId) throws Exception {
        byte[] iv = generateIV();
        long timestamp = Instant.now().toEpochMilli();
        byte[] nonce = generateNonce();

        // Prepare plaintext: [timestamp][nonce][userId length][userId][data]
        byte[] userIdBytes = userId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteBuffer plainBuf = ByteBuffer.allocate(8 + NONCE_LENGTH + 4 + userIdBytes.length + data.length);
        plainBuf.putLong(timestamp);
        plainBuf.put(nonce);
        plainBuf.putInt(userIdBytes.length);
        plainBuf.put(userIdBytes);
        plainBuf.put(data);
        byte[] plainWithMetadata = plainBuf.array();

        // Encrypt with AES-GCM
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        byte[] ciphertext;
        try {
            ciphertext = cipher.doFinal(plainWithMetadata);
        } finally {
            zeroArray(plainWithMetadata);
        }

        // Calculate HMAC over [version][IV][ciphertext]
        ByteBuffer toHmac = ByteBuffer.allocate(1 + iv.length + ciphertext.length);
        toHmac.put(VERSION);
        toHmac.put(iv);
        toHmac.put(ciphertext);
        byte[] hmac = calculateHMAC(toHmac.array(), hmacKey);

        // Final structure: [version][IV][ciphertext][HMAC]
        ByteBuffer finalBuf = ByteBuffer.allocate(1 + iv.length + ciphertext.length + hmac.length);
        finalBuf.put(VERSION);
        finalBuf.put(iv);
        finalBuf.put(ciphertext);
        finalBuf.put(hmac);

        return Base64.getEncoder().encodeToString(finalBuf.array());
    }
    
    /**
     * Decrypts data and verifies HMAC.
     * 
     * @param input base64-encoded encrypted data
     * @param aesKey AES decryption key
     * @param hmacKey HMAC key for verification
     * @param maxAgeMillis Maximum age tolerance
     * @return decrypted data with userId
     */
    public static DecryptedDataWithUser decryptWithHMAC(String input, SecretKey aesKey, SecretKey hmacKey, long maxAgeMillis) throws Exception {
        byte[] all = Base64.getDecoder().decode(input);
        
        // HMAC is last 32 bytes (SHA256 output)
        int hmacLength = 32;
        if (all.length < 1 + IV_LENGTH + 16 + hmacLength) {
            throw new SecurityException("Invalid encrypted data: too short");
        }
        
        // Extract components
        int hmacStart = all.length - hmacLength;
        byte[] dataWithoutHmac = new byte[hmacStart];
        byte[] receivedHmac = new byte[hmacLength];
        System.arraycopy(all, 0, dataWithoutHmac, 0, hmacStart);
        System.arraycopy(all, hmacStart, receivedHmac, 0, hmacLength);
        
        // Verify HMAC first
        byte[] calculatedHmac = calculateHMAC(dataWithoutHmac, hmacKey);
        if (!java.security.MessageDigest.isEqual(receivedHmac, calculatedHmac)) {
            throw new SecurityException("HMAC verification failed - data may be tampered");
        }
        
        // Extract version, IV, and ciphertext
        byte version = dataWithoutHmac[0];
        if (version != VERSION) {
            throw new SecurityException("Invalid version");
        }
        
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(dataWithoutHmac, 1, iv, 0, IV_LENGTH);
        
        byte[] ciphertext = new byte[dataWithoutHmac.length - 1 - IV_LENGTH];
        System.arraycopy(dataWithoutHmac, 1 + IV_LENGTH, ciphertext, 0, ciphertext.length);
        
        // Decrypt
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        byte[] plainWithMetadata;
        try {
            plainWithMetadata = cipher.doFinal(ciphertext);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new SecurityException("Decryption failed - data corrupted", e);
        }
        
        // Extract metadata and data
        ByteBuffer plainBuf = ByteBuffer.wrap(plainWithMetadata);
        long timestamp = plainBuf.getLong();
        byte[] nonce = new byte[NONCE_LENGTH];
        plainBuf.get(nonce);
        
        // Verify freshness
        long now = Instant.now().toEpochMilli();
        if (timestamp < 0 || timestamp > now + CLOCK_DRIFT_TOLERANCE) {
            zeroArray(plainWithMetadata);
            throw new SecurityException("Invalid timestamp");
        }
        if (now - timestamp > maxAgeMillis) {
            zeroArray(plainWithMetadata);
            throw new SecurityException("Data expired");
        }
        
        // Replay protection
        String nonceKey = Base64.getEncoder().encodeToString(nonce);
        Long expires = usedNonces.putIfAbsent(nonceKey, now + maxAgeMillis + CLOCK_DRIFT_TOLERANCE);
        if (expires != null) {
            zeroArray(plainWithMetadata);
            throw new SecurityException("Replay attack detected");
        }
        
        // Extract userId
        int userIdLen = plainBuf.getInt();
        byte[] userIdBytes = new byte[userIdLen];
        plainBuf.get(userIdBytes);
        String userId = new String(userIdBytes, java.nio.charset.StandardCharsets.UTF_8);
        
        // Extract actual data
        byte[] data = new byte[plainWithMetadata.length - 8 - NONCE_LENGTH - 4 - userIdLen];
        plainBuf.get(data);
        
        return new DecryptedDataWithUser(data, userId, timestamp);
    }
    
    /**
     * Calculate HMAC-SHA256
     */
    private static byte[] calculateHMAC(byte[] data, SecretKey hmacKey) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance(HMAC_ALGORITHM);
        mac.init(hmacKey);
        return mac.doFinal(data);
    }
    
    /**
     * Result class for decrypted data with user information
     */
    public static class DecryptedDataWithUser {
        public final byte[] data;
        public final String userId;
        public final long timestamp;
        
        public DecryptedDataWithUser(byte[] data, String userId, long timestamp) {
            this.data = data;
            this.userId = userId;
            this.timestamp = timestamp;
        }
    }

    /**
     * Encrypts arbitrary data, adds a timestamp for freshness, and returns a base64-encoded structure.
     * Structure: [version (1 byte)][IV (12 bytes)][ciphertext (variable)]
     * 
     * AES-GCM provides both confidentiality and authenticity, so no separate HMAC is needed.
     * The GCM authentication tag is included in the ciphertext.
     *
     * @param data The data to encrypt (as byte[])
     * @param key The AES key
     * @return base64-encoded string of the structure
     */
    public static String encrypt(byte[] data, SecretKey key) throws Exception {
        return encrypt(data, key, null);
    }
    
    /**
     * Encrypts arbitrary data with optional Associated Authenticated Data (AAD).
     * AAD is authenticated but not encrypted - useful for metadata like filenames, user IDs, etc.
     * 
     * @param data The data to encrypt (as byte[])
     * @param key The AES key
     * @param aad Optional associated authenticated data (can be null)
     * @return base64-encoded string of the structure
     */
    public static String encrypt(byte[] data, SecretKey key, byte[] aad) throws Exception {
        byte[] iv = generateIV();
        long timestamp = Instant.now().toEpochMilli();
        byte[] nonce = generateNonce();

        // Prepare plaintext: [timestamp (8 bytes)] [nonce (12 bytes)] + data 
        ByteBuffer plainBuf = ByteBuffer.allocate(8 + NONCE_LENGTH + data.length);
        plainBuf.putLong(timestamp);
        plainBuf.put(nonce);
        plainBuf.put(data);
        byte[] plainWithTimestampAndNonce = plainBuf.array();

        // Encrypt with AES-GCM (provides both confidentiality and authenticity)
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
        }
        byte[] ciphertext;
        try {
            ciphertext = cipher.doFinal(plainWithTimestampAndNonce);
        } catch (Exception e) {
            zeroArray(plainWithTimestampAndNonce);
            throw new SecurityException("Operation failed", e);
        } finally {
            zeroArray(plainWithTimestampAndNonce);
        }

        // Final structure: [version][IV][ciphertext with GCM tag]
        ByteBuffer finalBuf = ByteBuffer.allocate(1 + iv.length + ciphertext.length);
        finalBuf.put(VERSION);
        finalBuf.put(iv);
        finalBuf.put(ciphertext);
        byte[] result = finalBuf.array();

        return Base64.getEncoder().encodeToString(result);
    }


    /**
     * Decrypts the base64-encoded structure, verifies authenticity (via GCM tag) and freshness.
     * Throws SecurityException if authentication fails or message is stale.
     *
     * @param input base64-encoded structure
     * @param key AES key
     * @param maxAgeMillis Maximum allowed age for freshness (e.g., 5*60*1000 for 5 minutes)
     * @return decrypted data (byte[])
     */
    public static byte[] decrypt(String input, SecretKey key, long maxAgeMillis) throws Exception {
        return decrypt(input, key, maxAgeMillis, null);
    }
    
    /**
     * Decrypts with optional AAD verification.
     * 
     * @param input base64-encoded structure
     * @param key AES key
     * @param maxAgeMillis Maximum allowed age for freshness
     * @param aad Associated authenticated data (must match what was used in encrypt)
     * @return decrypted data (byte[])
     */
    public static byte[] decrypt(String input, SecretKey key, long maxAgeMillis, byte[] aad) throws Exception {
        byte[] all = Base64.getDecoder().decode(input);
        VerificationResult result = verifySafety(all, key, maxAgeMillis, aad);
        // Now just extract the data (timestamp and nonce already checked)
        ByteBuffer plainBuf = ByteBuffer.wrap(result.plainWithTimestamp);
        plainBuf.getLong(); // skip timestamp
        byte[] nonce = new byte[NONCE_LENGTH];
        plainBuf.get(nonce); // skip nonce
        byte[] data = new byte[result.plainWithTimestamp.length - 8 - NONCE_LENGTH];
        plainBuf.get(data);
        return data;
    }

    /**
     * Verifies the authenticity (via AES-GCM tag) and freshness of the document.
     * Throws SecurityException if authentication fails or message is stale.
     * Returns a VerificationResult with iv, ciphertext, and decrypted plaintext (with timestamp).
     * 
     * @param all The encrypted data bytes
     * @param aesKey The AES key
     * @param maxAgeMillis Maximum age tolerance
     * @param aad Optional associated authenticated data
     */
    public static VerificationResult verifySafety(byte[] all, SecretKey aesKey, long maxAgeMillis, byte[] aad) throws Exception {
        if (all.length < 1 + IV_LENGTH + 16) { // version + IV + min GCM tag
            throw new SecurityException("Verification failed: invalid input");
        }
        // Extract version, IV, and ciphertext
        byte version = all[0];
        if (version != VERSION) {
            throw new SecurityException("Verification failed: invalid format");
        }
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(all, 1, iv, 0, IV_LENGTH);
        byte[] ciphertext = new byte[all.length - 1 - IV_LENGTH];
        System.arraycopy(all, 1 + IV_LENGTH, ciphertext, 0, ciphertext.length);

        // Decrypt and verify authenticity with AES-GCM
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
        }
        byte[] plainWithTimestampAndNonce;
        try {
            plainWithTimestampAndNonce = cipher.doFinal(ciphertext);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new SecurityException("Verification failed", e);
        } catch (Exception e) {
            throw new SecurityException("Verification failed", e);
        }
        // Check timestamp and nonce validity and freshness
        if (plainWithTimestampAndNonce.length < 8 + NONCE_LENGTH) {
            zeroArray(plainWithTimestampAndNonce);
            throw new SecurityException("Verification failed");
        }
        ByteBuffer plainBuf = ByteBuffer.wrap(plainWithTimestampAndNonce);
        long timestamp = plainBuf.getLong();
        byte[] nonce = new byte[NONCE_LENGTH];
        plainBuf.get(nonce);
        long now = Instant.now().toEpochMilli();
        if (timestamp < 0 || timestamp > now + CLOCK_DRIFT_TOLERANCE) {
            zeroArray(plainWithTimestampAndNonce);
            throw new SecurityException("Verification failed");
        }
        if (now - timestamp > maxAgeMillis) {
            zeroArray(plainWithTimestampAndNonce);
            throw new SecurityException("Verification failed");
        }
        // Replay protection: check and store nonce
        String nonceKey = Base64.getEncoder().encodeToString(nonce);
        Long expires = usedNonces.putIfAbsent(nonceKey, now + maxAgeMillis + CLOCK_DRIFT_TOLERANCE);
        if (expires != null) {
            zeroArray(plainWithTimestampAndNonce);
            throw new SecurityException("Verification failed: replay detected");
        }
        return new VerificationResult(iv, ciphertext, plainWithTimestampAndNonce);
    }

    /**
     * Generates a cryptographically secure random nonce for replay protection.
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        SECURE_RANDOM.nextBytes(nonce);
        return nonce;
    }

    // Helper class for verification result
    public static class VerificationResult {
        public final byte[] iv;
        public final byte[] ciphertext;
        public final byte[] plainWithTimestamp;
        public VerificationResult(byte[] iv, byte[] ciphertext, byte[] plainWithTimestamp) {
            this.iv = iv;
            this.ciphertext = ciphertext;
            this.plainWithTimestamp = plainWithTimestamp;
        }
    }


    /**
     * Generates a cryptographically secure random IV.
     * Uses a shared SecureRandom instance for better performance.
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }
    
    /**
     * Zeros out a byte array to remove sensitive data from memory.
     * Note: This doesn't guarantee removal due to GC and JVM optimization,
     * but it's a best-effort approach.
     */
    private static void zeroArray(byte[] array) {
        if (array != null) {
            java.util.Arrays.fill(array, (byte) 0);
        }
    }


    public static SecretKey getKeyFromBytes(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, AES);
    }



    // ---- Command-line interface ----
    public static void main(String[] args) {
        java.util.Scanner scanner = new java.util.Scanner(System.in);
        System.out.println("Crypto-utilities interactive CLI. Type 'help' for commands, 'exit' to quit.");
        while (true) {
            System.out.print("> ");
            String line = scanner.nextLine();
            if (line == null) break;
            String[] inputArgs = line.trim().split("\\s+");
            if (inputArgs.length == 0 || inputArgs[0].isEmpty()) continue;
            String cmd = inputArgs[0].toLowerCase();
            if (cmd.equals("exit")) {
                System.out.println("Exiting Crypto-utilities CLI.");
                break;
            }
            try {
                switch (cmd) {
                    case "help":
                        printCliHelp();
                        break;
                    case "protect":
                        if (inputArgs.length < 4) {
                            System.err.println("Usage: Crypto-utilities protect <input-file> <aes-key-file> <output-file>");
                            break;
                        }
                        cliProtect(inputArgs[1], inputArgs[2], inputArgs[3]);
                        break;
                    case "check":
                        if (inputArgs.length < 3) {
                            System.err.println("Usage: Crypto-utilities check <input-file> <aes-key-file>");
                            break;
                        }
                        cliCheck(inputArgs[1], inputArgs[2]);
                        break;
                    case "unprotect":
                        if (inputArgs.length < 4) {
                            System.err.println("Usage: Crypto-utilities unprotect <input-file> <aes-key-file> <output-file>");
                            break;
                        }
                        cliUnprotect(inputArgs[1], inputArgs[2], inputArgs[3]);
                        break;
                    case "generateaeskey":
                        if (inputArgs.length < 2) {
                            System.err.println("Usage: Crypto-utilities generateAESKey <output-file>");
                            break;
                        }
                        cliGenerateAESKey(inputArgs[1]);
                        break;
                    case "generatehmackey":
                        if (inputArgs.length < 2) {
                            System.err.println("Usage: Crypto-utilities generateHMACKey <user-id>");
                            break;
                        }
                        cliGenerateHMACKey(inputArgs[1]);
                        break;
                    case "inithmackeys":
                        if (inputArgs.length < 2) {
                            System.err.println("Usage: Crypto-utilities initHMACKeys <user1> <user2> ...");
                            break;
                        }
                        String[] users = java.util.Arrays.copyOfRange(inputArgs, 1, inputArgs.length);
                        initializeHMACKeys(users);
                        break;
                    default:
                        System.err.println("Unknown command: " + cmd);
                        printCliHelp();
                }
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        }
        scanner.close();
    }

    private static void printCliHelp() {
        System.out.println("Crypto-utilities CLI - Available commands:");
        System.out.println("  Crypto-utilities help");
        System.out.println("    Display all commands and descriptions.");
        System.out.println("  Crypto-utilities generateAESKey <output-file>");
        System.out.println("    Generates a random AES key (256 bits) and saves it to the specified file in the 'keys' folder (base64-encoded).");
        System.out.println("  Crypto-utilities generateHMACKey <user-id>");
        System.out.println("    Generates a static HMAC key for a specific user (buyer/seller) and saves to keys/hmac/.");
        System.out.println("  Crypto-utilities initHMACKeys <user1> <user2> ...");
        System.out.println("    Initializes HMAC keys for multiple users at once (e.g., 'Lays Chips' 'Stealing Corporation').");
        System.out.println("  Crypto-utilities protect <input-file> <aes-key-file> <output-file>");
        System.out.println("    Encrypts and protects the input file using AES-GCM (provides confidentiality and authenticity).");
        System.out.println("  Crypto-utilities check <input-file> <aes-key-file>");
        System.out.println("    Verifies the integrity, authenticity, and freshness of the protected file.");
        System.out.println("  Crypto-utilities unprotect <input-file> <aes-key-file> <output-file>");
        System.out.println("    Decrypts and verifies the protected file, writing the original data to the output file.");
        System.out.println();
        System.out.println("All keys must be base64-encoded. For check/unprotect, a 5-minute freshness window is enforced.");
        System.out.println("HMAC keys are stored per-user in keys/hmac/ directory for transaction authentication.");
        System.out.println("Structure: [version (1 byte)][IV (12 bytes)][ciphertext with GCM authentication tag]");
    }

    private static void cliProtect(String inputFile, String aesKeyPath, String outputFile) throws Exception {
        SecretKey aesKey = readKeyFromFile(aesKeyPath, AES);
        byte[] data = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(inputFile));
        String encrypted = encrypt(data, aesKey);
        java.nio.file.Files.writeString(java.nio.file.Paths.get(outputFile), encrypted);
        System.out.println("File protected and written to " + outputFile);
    }

    private static void cliCheck(String inputFile, String aesKeyPath) throws Exception {
        SecretKey aesKey = readKeyFromFile(aesKeyPath, AES);
        String encrypted = java.nio.file.Files.readString(java.nio.file.Paths.get(inputFile));
        byte[] all = Base64.getDecoder().decode(encrypted);
        verifySafety(all, aesKey, 5 * 60 * 1000, null);
        System.out.println("File is safe: integrity, authenticity, and freshness verified.");
    }

    private static void cliUnprotect(String inputFile, String aesKeyPath, String outputFile) throws Exception {
        SecretKey aesKey = readKeyFromFile(aesKeyPath, AES);
        String encrypted = java.nio.file.Files.readString(java.nio.file.Paths.get(inputFile));
        byte[] decrypted = decrypt(encrypted, aesKey, 5 * 60 * 1000);
        java.nio.file.Files.write(java.nio.file.Paths.get(outputFile), decrypted);
        System.out.println("File unprotected and written to " + outputFile);
    }

    //key generation directories are in the wrong place
    private static void cliGenerateAESKey(String outputFile) throws Exception {
        SecretKey key = generateAESKey(256);
        String b64 = Base64.getEncoder().encodeToString(key.getEncoded());
        java.nio.file.Files.createDirectories(java.nio.file.Paths.get("keys"));
        java.nio.file.Files.writeString(java.nio.file.Paths.get("keys/" + outputFile), b64);
        System.out.println("AES key generated and saved to keys/" + outputFile);
    }
    
    private static void cliGenerateHMACKey(String userId) throws Exception {
        SecretKey hmacKey = generateHMACKey();
        saveHMACKey(hmacKey, userId);
        System.out.println("HMAC key generated for user: " + userId);
    }


    public static SecretKey readKeyFromFile(String file, String algorithm) throws Exception {
        String b64 = java.nio.file.Files.readString(java.nio.file.Paths.get(file));
        byte[] keyBytes = Base64.getDecoder().decode(b64.trim());
        return new SecretKeySpec(keyBytes, algorithm);
    }
    
    /**
     * Save HMAC key to file for a specific user.
     * Keys are stored in keys/hmac/ directory.
     */
    public static void saveHMACKey(SecretKey hmacKey, String userId) throws Exception {
        String b64 = Base64.getEncoder().encodeToString(hmacKey.getEncoded());
        java.nio.file.Path hmacDir = java.nio.file.Paths.get("keys/hmac");
        java.nio.file.Files.createDirectories(hmacDir);
        String filename = userId.toLowerCase().replace(" ", "-") + "-hmac.key";
        java.nio.file.Files.writeString(hmacDir.resolve(filename), b64);
        System.out.println("HMAC key saved to keys/hmac/" + filename);
    }
    
    /**
     * Load HMAC key from file for a specific user.
     */
    public static SecretKey loadHMACKey(String userId) throws Exception {
        String filename = userId.toLowerCase().replace(" ", "-") + "-hmac.key";
        java.nio.file.Path keyPath = java.nio.file.Paths.get("keys/hmac", filename);
        if (!java.nio.file.Files.exists(keyPath)) {
            throw new java.io.FileNotFoundException("HMAC key not found for user: " + userId);
        }
        return readKeyFromFile(keyPath.toString(), HMAC_ALGORITHM);
    }
    
    /**
     * Initialize HMAC keys for all parties in the system.
     * Should be run once to generate keys for buyer, seller, and any other parties.
     */
    public static void initializeHMACKeys(String... userIds) throws Exception {
        System.out.println("Initializing HMAC keys for users...");
        for (String userId : userIds) {
            SecretKey hmacKey = generateHMACKey();
            saveHMACKey(hmacKey, userId);
        }
        System.out.println("HMAC keys initialized successfully for " + userIds.length + " users.");
    }

}
