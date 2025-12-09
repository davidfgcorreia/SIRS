package com.chainofproduct.client;

import com.chainofproduct.utils.Request;
import org.junit.BeforeClass;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Test;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.List;
import java.util.ArrayList;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyBoolean;

public class ClientOperationsTest {
    private static BlockingQueue<Request> sendQueue;
    private static Object sendLock;
    private static List<Request> requestList;
    private static ClientOperations clientOps;

    private static org.mockito.MockedStatic<com.chainofproduct.utils.ResolveDestinations> resolveDestinationsMock;
    private static org.mockito.MockedStatic<com.chainofproduct.utils.Cerificates> cerificatesMock;
    private static org.mockito.MockedStatic<com.chainofproduct.utils.ApiCalls> apiCallsMock;

    @BeforeClass
    public static void setUp() throws Exception {
        requestList = new ArrayList<>();
        sendQueue = new LinkedBlockingQueue<Request>() {
            @Override
            public void put(Request req) {
                requestList.add(req);
            }
        };
        sendLock = new Object();

        // Mock ResolveDestinations.resolve to return a dummy DestinationInfo
        com.chainofproduct.utils.ResolveDestinations.DestinationInfo mockDestInfo =
            new com.chainofproduct.utils.ResolveDestinations.DestinationInfo("127.0.0.1", 12345, 13345, 14345);
        resolveDestinationsMock = mockStatic(com.chainofproduct.utils.ResolveDestinations.class);
        when(com.chainofproduct.utils.ResolveDestinations.resolve(anyString())).thenReturn(mockDestInfo);

        // Mock Cerificates.verifyCertificaAndObtain to do nothing
        cerificatesMock = mockStatic(com.chainofproduct.utils.Cerificates.class);
        doNothing().when(com.chainofproduct.utils.Cerificates.class);
        com.chainofproduct.utils.Cerificates.verifyCertificaAndObtain(anyString(), anyString(), anyString(), anyInt());

        clientOps = new ClientOperations(sendQueue, sendLock, "client42");
        // Mock ApiCalls.actAsSender to return a fake response for double signature
        apiCallsMock = mockStatic(com.chainofproduct.utils.ApiCalls.class);
        // Default: Return both 'my signature' and 'partner signature' as Strings
        when(com.chainofproduct.utils.ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), anyString(), any(byte[].class)))
            .thenReturn("my_signature:mysig,partner_signature:partnersig".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

        @AfterClass
        public static void cleanUpMocks() {
            if (resolveDestinationsMock != null) resolveDestinationsMock.close();
            if (cerificatesMock != null) cerificatesMock.close();
            if (apiCallsMock != null) apiCallsMock.close();
            org.mockito.Mockito.framework().clearInlineMocks();
        }
    @After
    public void tearDown() {
        requestList.clear();
        sendQueue.clear();
    }

    @Test
        public void testUpdateGroup() {
            System.out.println("[TEST] testUpdateGroup");
            requestList.clear();
            List<String> additions = new ArrayList<>();
            additions.add("CompanyA");
            additions.add("CompanyB");
            List<String> removals = new ArrayList<>();
            removals.add("CompanyC");
            removals.add("CompanyD");
            clientOps.updateGroup("TestGroup", additions, removals);
            assertFalse(requestList.isEmpty());
            Request req = requestList.get(0);
            assertEquals("127.0.0.1", req.getHost());
            assertEquals(12345, req.getPort());
            assertEquals("client", req.getEntityType());
            assertEquals(42, req.getClientNum());
            assertEquals("server", req.getReceiverEntity());
            String payload = new String(req.getDataFile(), java.nio.charset.StandardCharsets.UTF_8);
            System.out.println("[testUpdateGroup] Payload: " + payload);
            assertTrue(payload.contains("\"request_type\": \"groupUpdate\""));
            assertTrue(payload.contains("\"source\": \"client42\""));
            assertTrue(payload.contains("\"group\": \"TestGroup\""));
            assertTrue(payload.contains("\"groupAdditions\": [\"CompanyA\", \"CompanyB\"]"));
            assertTrue(payload.contains("\"groupRemove\": [\"CompanyC\", \"CompanyD\"]"));
            System.out.println("[testUpdateGroup] All assertions passed.");
        }


    // Extracts the value of a JSON string field (with double quotes)
    private String extractRequestType(String payload) {
        // Look for "request_type":"..."
        String key = "\"request_type\":";
        int idx = payload.indexOf(key);
        if (idx == -1) return null;
        int start = payload.indexOf('"', idx + key.length());
        if (start == -1) return null;
        int end = payload.indexOf('"', start + 1);
        if (end == -1) return null;
        return payload.substring(start + 1, end);
    }

    

    @Test
    public void testSendTransaction() throws Exception {
        System.out.println("[TEST] testSendTransaction");
        // Prepare a dummy transaction file with valid JSON and seller/buyer fields
        String fileContent = "{\"id\":123,\"timestamp\":17663363400,\"seller\":\"client42\",\"buyer\":\"destination42\",\"product\":\"Indium\",\"units\":40000,\"amount\":90000000}";
        java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("testtransaction", ".json");
        java.nio.file.Files.write(tempFile, fileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        // Use a mock subclass to override obtainDoubleSignature
        ClientOperations mockOps = new ClientOperations(sendQueue, sendLock, "client42") {
            @Override
            public String[] obtainDoubleSignature(byte[] transactionData, String PartnerHost, int PartnerPort, String PartnerName, boolean isSeller) {
                return new String[]{"my_signature:mysig", "partner_signature:partnersig"};
            }
        };

        // Use the correct buyer as the destination, and set group=true
        mockOps.sendtrsaction(tempFile.toString(), "someotherClinet", false);
        assertFalse(requestList.isEmpty());
        Request req = requestList.get(0);
        // Assert all fields of the Request object
        assertEquals("127.0.0.1", req.getHost());
        assertEquals(12345, req.getPort());
        assertEquals("client", req.getEntityType());
        assertEquals(42, req.getClientNum());
        assertEquals("server", req.getReceiverEntity());

        // Inspect the payload structure
        String payload = new String(req.getDataFile(), java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[testSendTransaction] Payload: " + payload);
        assertTrue(payload.startsWith("{\"request_type\": \"transaction\","));
        assertTrue(payload.contains("\"destination\": \"someotherClinet\","));
        // Assert group flag is present and set to false
        assertTrue(payload.contains("\"group\": false"));
        // Assert both signatures are present (since now they are appended, not in JSON)
        assertTrue(payload.contains("my_signature:mysig"));
        assertTrue(payload.contains("partner_signature:partnersig"));
        System.out.println("[testSendTransaction] All assertions passed.");

        java.nio.file.Files.delete(tempFile);
    }

    @Test
    public void testGetTransactionById() {
        System.out.println("[TEST] testGetTransactionById");
        requestList.clear();
        clientOps.gettransactionById(123L);
        assertFalse(requestList.isEmpty());
        Request req = requestList.get(0);
        String payload = new String(req.getDataFile(), java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[testGetTransactionById] Payload: " + payload);
        assertTrue(payload.contains("\"request_type\":\"getById\""));
        assertEquals("getById", extractRequestType(payload));
        assertTrue(payload.contains("\"transaction_id\":123"));
        System.out.println("[testGetTransactionById] All assertions passed.");
    }

    @Test
    public void testGetAll() {
        System.out.println("[TEST] testGetAll");
        requestList.clear();
        clientOps.getAll();
        assertFalse(requestList.isEmpty());
        Request req = requestList.get(0);
        String payload = new String(req.getDataFile(), java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[testGetAll] Payload: " + payload);
        assertTrue(payload.contains("\"request_type\":\"getAll\""));
        assertEquals("getAll", extractRequestType(payload));
        System.out.println("[testGetAll] All assertions passed.");
    }

    @Test
    public void testGetShares() {
        System.out.println("[TEST] testGetShares");
        requestList.clear();
        clientOps.getShares(456L);
        assertFalse(requestList.isEmpty());
        Request req = requestList.get(0);
        String payload = new String(req.getDataFile(), java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[testGetShares] Payload: " + payload);
        assertTrue(payload.contains("\"request_type\":\"getShares\""));
        assertEquals("getShares", extractRequestType(payload));
        assertTrue(payload.contains("\"transaction_id\":456"));
        System.out.println("[testGetShares] All assertions passed.");
    }

    @Test
    public void testGetSharesBy() {
        System.out.println("[TEST] testGetSharesBy");
        requestList.clear();
        clientOps.getSharesBy(789L, "alice");
        assertFalse(requestList.isEmpty());
        Request req = requestList.get(0);
        String payload = new String(req.getDataFile(), java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[testGetSharesBy] Payload: " + payload);
        assertTrue(payload.contains("\"request_type\":\"getSharesBy\""));
        assertEquals("getSharesBy", extractRequestType(payload));
        assertTrue(payload.contains("\"shared_by\":\"alice\""));
        System.out.println("[testGetSharesBy] All assertions passed.");
    }

    @Test
    public void testGetRecentTransactionsSince() {
        System.out.println("[TEST] testGetRecentTransactionsSince");
        requestList.clear();
        clientOps.getRecentTransactionsSince(123456789L);
        assertFalse(requestList.isEmpty());
        Request req = requestList.get(0);
        String payload = new String(req.getDataFile(), java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[testGetRecentTransactionsSince] Payload: " + payload);
        assertTrue(payload.contains("\"request_type\":\"getRecentTransactions\""));
        assertEquals("getRecentTransactions", extractRequestType(payload));
        assertTrue(payload.contains("\"since\":123456789"));
        System.out.println("[testGetRecentTransactionsSince] All assertions passed.");
    }


    // Auxiliary function to create a signed transaction file with two distinct signatures
    private java.nio.file.Path createSignedTransactionFile(java.security.PrivateKey sellerPrivateKey, java.security.PrivateKey buyerPrivateKey, String seller, String buyer, String transactionId, boolean tamper) throws Exception {
        String json = String.format("{\"seller\":\"%s\",\"buyer\":\"%s\",\"transaction_id\":\"%s\"}", seller, buyer, transactionId);
        byte[] fileBytes = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] fileHash = digest.digest(fileBytes);

        // Seller signs
        java.security.Signature sellerSig = java.security.Signature.getInstance("SHA256withRSA");
        sellerSig.initSign(sellerPrivateKey);
        sellerSig.update(fileHash);
        byte[] sellerSignatureBytes = sellerSig.sign();
        String sellerSignatureB64 = java.util.Base64.getEncoder().encodeToString(sellerSignatureBytes);

        // Buyer signs
        java.security.Signature buyerSig = java.security.Signature.getInstance("SHA256withRSA");
        buyerSig.initSign(buyerPrivateKey);
        buyerSig.update(fileHash);
        byte[] buyerSignatureBytes = buyerSig.sign();
        String buyerSignatureB64 = java.util.Base64.getEncoder().encodeToString(buyerSignatureBytes);

        // Optionally tamper with the file
        if (tamper) {
            fileBytes[0] ^= 0xFF; // Flip first byte
        }

        String payload = "{request_type:transaction, destination:...}";
        byte[] payloadBytes = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] sellerSigBytes = sellerSignatureB64.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] buyerSigBytes = buyerSignatureB64.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] completeFile = new byte[payloadBytes.length + fileBytes.length + sellerSigBytes.length + buyerSigBytes.length];
        System.arraycopy(payloadBytes, 0, completeFile, 0, payloadBytes.length);
        System.arraycopy(fileBytes, 0, completeFile, payloadBytes.length, fileBytes.length);
        System.arraycopy(sellerSigBytes, 0, completeFile, payloadBytes.length + fileBytes.length, sellerSigBytes.length);
        System.arraycopy(buyerSigBytes, 0, completeFile, payloadBytes.length + fileBytes.length + sellerSigBytes.length, buyerSigBytes.length);

        java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("testfile", ".bin");
        java.nio.file.Files.write(tempFile, completeFile);
        return tempFile;
    }
    @Test
    public void testVerifyFileIntegrityTampered() throws Exception {
        System.out.println("[TEST] testVerifyFileIntegrityTampered");
        // Generate keypairs for seller and buyer
        java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        java.security.KeyPair sellerKeyPair = keyGen.generateKeyPair();
        java.security.KeyPair buyerKeyPair = keyGen.generateKeyPair();
        java.security.PrivateKey sellerPrivateKey = sellerKeyPair.getPrivate();
        java.security.PublicKey sellerPublicKey = sellerKeyPair.getPublic();
        java.security.PrivateKey buyerPrivateKey = buyerKeyPair.getPrivate();
        java.security.PublicKey buyerPublicKey = buyerKeyPair.getPublic();

        // Mock loadPublicKeyFromTruststore to return correct public key based on alias
        ClientOperations mockOps = new ClientOperations(sendQueue, sendLock, "client42") {
            public java.security.PublicKey loadPublicKeyFromTruststore(String truststorePath, String alias, String password) {
                if (alias.equals("client42")) return sellerPublicKey;
                if (alias.equals("buyer42")) return buyerPublicKey;
                return null;
            }
        };

        // Create a tampered signed file
        java.nio.file.Path tempFile = createSignedTransactionFile(sellerPrivateKey, buyerPrivateKey, "client42", "buyer42", "txid", true);

        boolean result = mockOps.verifyFileIntegrity(tempFile.toString());
        assertFalse(result);
        java.nio.file.Files.delete(tempFile);
        System.out.println("[testVerifyFileIntegrityTampered] All assertions passed.");
    }


    @Test
    public void testVerifyFileIntegrityValid() throws Exception {
        System.out.println("[TEST] testVerifyFileIntegrityValid");
        // Generate keypairs for seller and buyer
        java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        java.security.KeyPair sellerKeyPair = keyGen.generateKeyPair();
        java.security.KeyPair buyerKeyPair = keyGen.generateKeyPair();
        java.security.PrivateKey sellerPrivateKey = sellerKeyPair.getPrivate();
        java.security.PublicKey sellerPublicKey = sellerKeyPair.getPublic();
        java.security.PrivateKey buyerPrivateKey = buyerKeyPair.getPrivate();
        java.security.PublicKey buyerPublicKey = buyerKeyPair.getPublic();

        // Mock loadPublicKeyFromTruststore to return correct public key based on alias
        ClientOperations mockOps = new ClientOperations(sendQueue, sendLock, "client42") {
            public java.security.PublicKey loadPublicKeyFromTruststore(String truststorePath, String alias, String password) {
                if (alias.equals("client42")) return sellerPublicKey;
                if (alias.equals("buyer42")) return buyerPublicKey;
                return null;
            }
        };
        // Create a valid signed file
        java.nio.file.Path tempFile = createSignedTransactionFile(sellerPrivateKey, buyerPrivateKey, "client42", "buyer42", "txid", false);

        boolean result = mockOps.verifyFileIntegrity(tempFile.toString());
        assertTrue(result);
        java.nio.file.Files.delete(tempFile);
        System.out.println("[testVerifyFileIntegrityValid] All assertions passed.");
    }

    @Test
    public void testVerifyFileIntegrityAsThirdParty() throws Exception {
        System.out.println("[TEST] testVerifyFileIntegrityAsThirdParty");
        // Generate keypairs for seller and buyer
        java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        java.security.KeyPair sellerKeyPair = keyGen.generateKeyPair();
        java.security.KeyPair buyerKeyPair = keyGen.generateKeyPair();
        java.security.PrivateKey sellerPrivateKey = sellerKeyPair.getPrivate();
        java.security.PublicKey sellerPublicKey = sellerKeyPair.getPublic();
        java.security.PrivateKey buyerPrivateKey = buyerKeyPair.getPrivate();
        java.security.PublicKey buyerPublicKey = buyerKeyPair.getPublic();

        // Create a valid signed file (seller: client42, buyer: buyer42)
        java.nio.file.Path tempFile = createSignedTransactionFile(sellerPrivateKey, buyerPrivateKey, "client42", "buyer42", "txid", false);

        // Create a ClientOperations for a third party (not seller or buyer)
        ClientOperations mockOps = new ClientOperations(sendQueue, sendLock, "thirdParty") {
            @Override
            public java.security.PublicKey loadPublicKeyFromTruststore(String truststorePath, String alias, String password) {
                if (alias.equals("client42")) return sellerPublicKey;
                if (alias.equals("buyer42")) return buyerPublicKey;
                return null;
            }
        };

        boolean result = mockOps.verifyFileIntegrity(tempFile.toString());
        assertTrue(result);
        java.nio.file.Files.delete(tempFile);
        System.out.println("[testVerifyFileIntegrityAsThirdParty] All assertions passed.");
    }

    @Test
    public void testObtainDoubleSignature() throws Exception {
        System.out.println("[TEST] testObtainDoubleSignature");
        // Prepare dummy transaction data
        byte[] transactionData = "dummy transaction data".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // Subclass to override signTransactionData
        ClientOperations mockOps = new ClientOperations(sendQueue, sendLock, "client42") {
            @Override
            protected String signTransactionData(byte[] transactionData) {
                return "SELLER_SIG";
            }
        };

        // Set specific mock for this test
        reset(com.chainofproduct.utils.ApiCalls.class);
        when(com.chainofproduct.utils.ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), anyString(), any(byte[].class)))
            .thenReturn("{\"signature\":\"BUYER_SIG\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        String[] sigs = mockOps.obtainDoubleSignature(transactionData, "host", 12345, "buyer42", true);
        assertNotNull("Signature array should not be null", sigs);
        assertEquals(2, sigs.length);
        assertEquals("SELLER_SIG", sigs[0]);
        assertEquals("BUYER_SIG", sigs[1]);
        System.out.println("[testObtainDoubleSignature_Mocked] All assertions passed.");
    }

}