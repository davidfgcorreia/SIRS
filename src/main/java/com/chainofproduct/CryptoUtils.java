package com.chainofproduct;


import javax.crypto.Cipher;
import java.security.MessageDigest;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.security.SecureRandom;
import java.util.Base64;
import java.nio.ByteBuffer;
import java.time.Instant;

public class CryptoUtils {
    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static SecretKey generateAESKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(keySize);
        return keyGen.generateKey();
    }


    /**
     * Encrypts arbitrary data, adds a timestamp for freshness, and returns a base64-encoded structure containing:
     * [IV (12 bytes)][timestamp (8 bytes)][ciphertext (variable)][HMAC (32 bytes)]
     *
     * @param data The data to encrypt (as byte[])
     * @param key The AES key
     * @param hmacKey The HMAC key
     * @return base64-encoded string of the structure
     */
    public static String encrypt(byte[] data, SecretKey key, SecretKey hmacKey) throws Exception {
        byte[] iv = generateIV();
        long timestamp = Instant.now().toEpochMilli();

        // Prepare plaintext: [timestamp (8 bytes)] + data
        ByteBuffer plainBuf = ByteBuffer.allocate(8 + data.length);
        plainBuf.putLong(timestamp);
        plainBuf.put(data);
        byte[] plainWithTimestamp = plainBuf.array();

        // Encrypt
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertext = cipher.doFinal(plainWithTimestamp);

        // Prepare output: [IV][ciphertext]
        ByteBuffer outBuf = ByteBuffer.allocate(iv.length + ciphertext.length);
        outBuf.put(iv);
        outBuf.put(ciphertext);
        byte[] ivAndCiphertext = outBuf.array();

        // Compute HMAC over [IV][ciphertext]
        byte[] hmac = computeHMAC(ivAndCiphertext, hmacKey);

        // Final structure: [IV][ciphertext][HMAC]
        ByteBuffer finalBuf = ByteBuffer.allocate(ivAndCiphertext.length + hmac.length);
        finalBuf.put(ivAndCiphertext);
        finalBuf.put(hmac);
        byte[] result = finalBuf.array();

        return Base64.getEncoder().encodeToString(result);
    }


    /**
     * Decrypts the base64-encoded structure, verifies HMAC and freshness, and returns the decrypted data (byte[]).
     * Throws SecurityException if HMAC fails or message is stale.
     *
     * @param input base64-encoded structure
     * @param key AES key
     * @param hmacKey HMAC key
     * @param maxAgeMillis Maximum allowed age for freshness (e.g., 5*60*1000 for 5 minutes)
     * @return decrypted data (byte[])
     */
    public static byte[] decrypt(String input, SecretKey key, SecretKey hmacKey, long maxAgeMillis) throws Exception {
        byte[] all = Base64.getDecoder().decode(input);
        VerificationResult result = verifySafety(all, key, hmacKey, maxAgeMillis);
        // Now just extract the data (timestamp already checked)
        ByteBuffer plainBuf = ByteBuffer.wrap(result.plainWithTimestamp);
        plainBuf.getLong(); // skip timestamp
        byte[] data = new byte[result.plainWithTimestamp.length - 8];
        plainBuf.get(data);
        return data;
    }

    /**
     * Verifies the HMAC and freshness of the document. Throws SecurityException if not safe.
     * Returns a VerificationResult with iv, ciphertext, and decrypted plaintext (with timestamp).
     */
    public static VerificationResult verifySafety(byte[] all, SecretKey aesKey, SecretKey hmacKey, long maxAgeMillis) throws Exception {
        if (all.length < IV_LENGTH + 32) throw new IllegalArgumentException("Input too short");
        // Extract IV, ciphertext, HMAC
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(all, 0, iv, 0, IV_LENGTH);
        byte[] hmac = new byte[32];
        System.arraycopy(all, all.length - 32, hmac, 0, 32);
        byte[] ciphertext = new byte[all.length - IV_LENGTH - 32];
        System.arraycopy(all, IV_LENGTH, ciphertext, 0, ciphertext.length);

        // Verify HMAC
        ByteBuffer hmacBuf = ByteBuffer.allocate(IV_LENGTH + ciphertext.length);
        hmacBuf.put(iv);
        hmacBuf.put(ciphertext);
        byte[] hmacInput = hmacBuf.array();
        byte[] computedHmac = computeHMAC(hmacInput, hmacKey);
        if (!MessageDigest.isEqual(hmac, computedHmac)) {
            throw new SecurityException("HMAC verification failed: data may have been tampered with.");
        }

        // Decrypt to get timestamp for freshness check
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        byte[] plainWithTimestamp = cipher.doFinal(ciphertext);
        ByteBuffer plainBuf = ByteBuffer.wrap(plainWithTimestamp);
        long timestamp = plainBuf.getLong();
        long now = Instant.now().toEpochMilli();
        if (now - timestamp > maxAgeMillis) {
            throw new SecurityException("Message is stale");
        }

        return new VerificationResult(iv, ciphertext, plainWithTimestamp);
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


       public static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }


    public static SecretKey getKeyFromBytes(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, AES);
    }

    // HMAC helpers
    public static byte[] computeHMAC(byte[] data, SecretKey hmacKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        return mac.doFinal(data);
    }

    public static SecretKey generateHMACKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // ---- Command-line interface ----
    public static void main(String[] args) {
        java.util.Scanner scanner = new java.util.Scanner(System.in);
        System.out.println("Cyprto-utilities interactive CLI. Type 'help' for commands, 'exit' to quit.");
        while (true) {
            System.out.print("> ");
            String line = scanner.nextLine();
            if (line == null) break;
            String[] inputArgs = line.trim().split("\\s+");
            if (inputArgs.length == 0 || inputArgs[0].isEmpty()) continue;
            String cmd = inputArgs[0].toLowerCase();
            if (cmd.equals("exit")) {
                System.out.println("Exiting Cyprto-utilities CLI.");
                break;
            }
            try {
                switch (cmd) {
                    case "help":
                        printCliHelp();
                        break;
                    case "protect":
                        if (inputArgs.length < 5) {
                            System.err.println("Usage: Cyprto-utilities protect <input-file> <aes-key-file> <hmac-key-file> <output-file>");
                            break;
                        }
                        cliProtect(inputArgs[1], inputArgs[2], inputArgs[3], inputArgs[4]);
                        break;
                    case "check":
                        if (inputArgs.length < 4) {
                            System.err.println("Usage: Cyprto-utilities check <input-file> <aes-key-file> <hmac-key-file>");
                            break;
                        }
                        cliCheck(inputArgs[1], inputArgs[2], inputArgs[3]);
                        break;
                    case "unprotect":
                        if (inputArgs.length < 5) {
                            System.err.println("Usage: Cyprto-utilities unprotect <input-file> <aes-key-file> <hmac-key-file> <output-file>");
                            break;
                        }
                        cliUnprotect(inputArgs[1], inputArgs[2], inputArgs[3], inputArgs[4]);
                        break;
                    case "generateaeskey":
                        if (inputArgs.length < 2) {
                            System.err.println("Usage: Cyprto-utilities generateAESKey <output-file>");
                            break;
                        }
                        cliGenerateAESKey(inputArgs[1]);
                        break;
                    case "generatehmackey":
                        if (inputArgs.length < 2) {
                            System.err.println("Usage: Cyprto-utilities generateHMACKey <output-file>");
                            break;
                        }
                        cliGenerateHMACKey(inputArgs[1]);
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
        System.out.println("Cyprto-utilities CLI - Available commands:");
        System.out.println("  Cyprto-utilities help");
        System.out.println("    Display all commands and descriptions.");
        System.out.println("  Cyprto-utilities generateAESKey <output-file>");
        System.out.println("    Generates a random AES key (256 bits) and saves it to the specified file in the 'keys' folder (base64-encoded).");
        System.out.println("  Cyprto-utilities generateHMACKey <output-file>");
        System.out.println("    Generates a random HMAC key (256 bits) and saves it to the specified file in the 'keys' folder (base64-encoded).");
        System.out.println("  Cyprto-utilities protect <input-file> <aes-key-file> <hmac-key-file> <output-file>");
        System.out.println("    Encrypts and protects the input file using the provided AES and HMAC keys (read from files), writing the result to the output file.");
        System.out.println("  Cyprto-utilities check <input-file> <aes-key-file> <hmac-key-file>");
        System.out.println("    Verifies the integrity, authenticity, and freshness of the protected file using the provided keys (read from files).");
        System.out.println("  Cyprto-utilities unprotect <input-file> <aes-key-file> <hmac-key-file> <output-file>");
        System.out.println("    Decrypts and verifies the protected file, writing the original data to the output file.");
        System.out.println();
        System.out.println("All keys must be base64-encoded. For check/unprotect, a 5-minute freshness window is enforced.");
    }

    private static void cliProtect(String inputFile, String aesKeyPath, String hmacKeyPath, String outputFile) throws Exception {
        SecretKey aesKey = readKeyFromFile(aesKeyPath, AES);
        SecretKey hmacKey = readKeyFromFile(hmacKeyPath, "HmacSHA256");
        byte[] data = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(inputFile));
        String encrypted = encrypt(data, aesKey, hmacKey);
        java.nio.file.Files.writeString(java.nio.file.Paths.get(outputFile), encrypted);
        System.out.println("File protected and written to " + outputFile);
    }

    private static void cliCheck(String inputFile, String aesKeyPath, String hmacKeyPath) throws Exception {
        SecretKey aesKey = readKeyFromFile(aesKeyPath, AES);
        SecretKey hmacKey = readKeyFromFile(hmacKeyPath, "HmacSHA256");
        String encrypted = java.nio.file.Files.readString(java.nio.file.Paths.get(inputFile));
        byte[] all = Base64.getDecoder().decode(encrypted);
        verifySafety(all, aesKey, hmacKey, 5 * 60 * 1000);
        System.out.println("File is safe: integrity, authenticity, and freshness verified.");
    }

    private static void cliUnprotect(String inputFile, String aesKeyPath, String hmacKeyPath, String outputFile) throws Exception {
        SecretKey aesKey = readKeyFromFile(aesKeyPath, AES);
        SecretKey hmacKey = readKeyFromFile(hmacKeyPath, "HmacSHA256");
        String encrypted = java.nio.file.Files.readString(java.nio.file.Paths.get(inputFile));
        byte[] decrypted = decrypt(encrypted, aesKey, hmacKey, 5 * 60 * 1000);
        java.nio.file.Files.write(java.nio.file.Paths.get(outputFile), decrypted);
        System.out.println("File unprotected and written to " + outputFile);
    }
    private static void cliGenerateAESKey(String outputFile) throws Exception {
        SecretKey key = generateAESKey(256);
        String b64 = Base64.getEncoder().encodeToString(key.getEncoded());
        java.nio.file.Files.createDirectories(java.nio.file.Paths.get("keys"));
        java.nio.file.Files.writeString(java.nio.file.Paths.get("keys/" + outputFile), b64);
        System.out.println("AES key generated and saved to keys/" + outputFile);
    }

    private static void cliGenerateHMACKey(String outputFile) throws Exception {
        SecretKey key = generateHMACKey();
        String b64 = Base64.getEncoder().encodeToString(key.getEncoded());
        java.nio.file.Files.createDirectories(java.nio.file.Paths.get("keys"));
        java.nio.file.Files.writeString(java.nio.file.Paths.get("keys/" + outputFile), b64);
        System.out.println("HMAC key generated and saved to keys/" + outputFile);
    }

    public static SecretKey readKeyFromFile(String file, String algorithm) throws Exception {
        String b64 = java.nio.file.Files.readString(java.nio.file.Paths.get(file));
        byte[] keyBytes = Base64.getDecoder().decode(b64.trim());
        return new SecretKeySpec(keyBytes, algorithm);
    }

}
