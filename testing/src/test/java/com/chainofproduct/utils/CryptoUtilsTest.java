package com.chainofproduct.utils;

import org.junit.Test;
import static org.junit.Assert.*;

public class CryptoUtilsTest {
    private javax.crypto.SecretKey aesKey;

    @org.junit.Before
    public void setUp() throws Exception {
        aesKey = CryptoUtils.generateAESKey(256);
    }

    @Test
    public void testEncryptDecrypt() throws Exception {
        byte[] data = "Hello, SIRS!".getBytes();
        byte[] encrypted = CryptoUtils.encrypt(data, aesKey);
        byte[] decrypted = CryptoUtils.decrypt(encrypted, aesKey, 5 * 60 * 1000);
        assertArrayEquals(data, decrypted);
    }

    @Test
    public void testNonceReplayProtection() throws Exception {
        byte[] data = "Replay Test".getBytes();
        byte[] encrypted = CryptoUtils.encrypt(data, aesKey);
        // First decrypt should succeed
        byte[] decrypted = CryptoUtils.decrypt(encrypted, aesKey, 5 * 60 * 1000);
        assertArrayEquals(data, decrypted);
        // Second decrypt should fail due to nonce replay
        try {
            CryptoUtils.decrypt(encrypted, aesKey, 5 * 60 * 1000);
            fail("Expected SecurityException for nonce replay");
        } catch (SecurityException e) {
            // Expected
        }
    }

    @Test
    public void testFreshnessCheck() throws Exception {
        byte[] data = "Freshness Test".getBytes();
        byte[] encrypted = CryptoUtils.encrypt(data, aesKey);
        // Simulate old timestamp by modifying encrypted bytes
        encrypted[15] = (byte)0; // crude way to break timestamp
        try {
            CryptoUtils.decrypt(encrypted, aesKey, 1);
            fail("Expected SecurityException for stale message");
        } catch (SecurityException e) {
            // Expected
        }
    }
    @Test
    public void testVerifyIntegrity() throws Exception {
        byte[] data = "Integrity Test".getBytes();
        byte[] encrypted = CryptoUtils.encrypt(data, aesKey);
        // Tamper with the encrypted message to break integrity
        encrypted[encrypted.length - 1] ^= 0xFF;
        try {
            CryptoUtils.verifySafety(encrypted, aesKey, 5 * 60 * 1000, null);
            fail("Expected SecurityException for tampered message");
        } catch (SecurityException e) {
            // Expected: integrity/authenticity check should fail
        }
    }
}
