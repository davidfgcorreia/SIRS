package com.chainofproduct.server;

import com.chainofproduct.utils.CryptoUtils;
import com.chainofproduct.utils.ApiCalls;

import org.junit.BeforeClass;
import org.junit.After;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import javax.crypto.SecretKey;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import org.mockito.MockedStatic;

public class ServerOperationsTest {
    private static ServerOperations serverOps;
    private static KeyPair sellerKeyPair;
    private static KeyPair buyerKeyPair;
    private static KeyPair serverKeyPair;
    private static SecretKey mockStorageKey;
    private static MockedStatic<CryptoUtils> cryptoUtilsMock;
    private static MockedStatic<ApiCalls> apiCallsMock;

    @BeforeClass
    public static void setUp() throws Exception {
        System.out.println("[SETUP] Initializing ServerOperationsTest");
        
        // Generate test key pairs
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        sellerKeyPair = keyGen.generateKeyPair();
        buyerKeyPair = keyGen.generateKeyPair();
        serverKeyPair = keyGen.generateKeyPair();
        
        // Generate a real AES key before mocking
        mockStorageKey = javax.crypto.KeyGenerator.getInstance("AES").generateKey();
        
        // Mock static methods
        cryptoUtilsMock = mockStatic(CryptoUtils.class);
        cryptoUtilsMock.when(() -> CryptoUtils.readKeyFromFile(anyString(), eq("AES"))).thenReturn(mockStorageKey);
        cryptoUtilsMock.when(() -> CryptoUtils.generateAESKey(anyInt())).thenReturn(mockStorageKey);
        cryptoUtilsMock.when(() -> CryptoUtils.encrypt(any(byte[].class), any(SecretKey.class))).thenAnswer(invocation -> {
            byte[] data = invocation.getArgument(0);
            if (data == null) {
                return new byte[]{1, 2, 3, 4}; // Return dummy data if null
            }
            return data; // Return as-is for testing
        });
        
        apiCallsMock = mockStatic(ApiCalls.class);
        
        // Create a subclass to override private key loading methods
        serverOps = new ServerOperations() {
            public PrivateKey loadPrivateKeyFromKeystore(String path, String password, String alias) throws Exception {
                return serverKeyPair.getPrivate();
            }
            
            public PublicKey loadPublicKeyFromKeystore(String path, String password, String alias) throws Exception {
                if (alias.contains("seller") || alias.contains("client42")) return sellerKeyPair.getPublic();
                if (alias.contains("buyer") || alias.contains("client43")) return buyerKeyPair.getPublic();
                return serverKeyPair.getPublic();
            }
        };
        
        System.out.println("[SETUP] ServerOperationsTest initialized");
    }

    @After
    public void tearDown() {
        // Reset mocks between tests
        apiCallsMock.clearInvocations();
    }
    
    @org.junit.AfterClass
    public static void tearDownClass() {
        if (cryptoUtilsMock != null) {
            cryptoUtilsMock.close();
        }
        if (apiCallsMock != null) {
            apiCallsMock.close();
        }
    }

    // Helper method to create signed transaction request
    private byte[] createSignedTransactionRequest(String source, long id, String seller, String buyer, 
                                                   String product, long units, long amount, PrivateKey signingKey) throws Exception {
        String transactionJson = String.format(
            "{\"id\":%d,\"timestamp\":%d,\"seller\":\"%s\",\"buyer\":\"%s\",\"product\":\"%s\",\"units\":%d,\"amount\":%d}",
            id, System.currentTimeMillis(), seller, buyer, product, units, amount
        );
        
        byte[] transactionBytes = transactionJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        
        // Sign the transaction
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(signingKey);
        sig.update(transactionBytes);
        byte[] signatureBytes = sig.sign();
        String signatureB64 = Base64.getEncoder().encodeToString(signatureBytes);
        
        // Build complete request: {request_type: transaction, source: X}[JSON]{signature:SIG}
        String header = String.format("{request_type: transaction, source: %s}", source);
        String signaturePart = String.format("{signature:%s}", signatureB64);
        
        byte[] headerBytes = header.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] sigBytes = signaturePart.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        
        byte[] fullRequest = new byte[headerBytes.length + transactionBytes.length + sigBytes.length];
        System.arraycopy(headerBytes, 0, fullRequest, 0, headerBytes.length);
        System.arraycopy(transactionBytes, 0, fullRequest, headerBytes.length, transactionBytes.length);
        System.arraycopy(sigBytes, 0, fullRequest, headerBytes.length + transactionBytes.length, sigBytes.length);
        
        return fullRequest;
    }

    // Verify seller can submit their own transaction
    @Test
    public void testHandleTransactionRequestValidSeller() throws Exception {
        System.out.println("[TEST] testHandleTransactionRequestValidSeller");
        
        // Mock database responses
        apiCallsMock.when(() -> ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), 
            anyString(), any(byte[].class))).thenReturn("{\"success\":true}".getBytes());
        
        byte[] request = createSignedTransactionRequest("client42", 1001L, "client42", "client43", 
            "Lithium", 5000, 1000000, sellerKeyPair.getPrivate());
        
        byte[] response = serverOps.processRequest(request);
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("success") || responseStr.contains("stored"));
        assertFalse(responseStr.contains("error"));
        
        System.out.println("[TEST] testHandleTransactionRequestValidSeller passed");
    }

    // Verify buyer can submit the same transaction (dual authorization)
    @Test
    public void testHandleTransactionRequestValidBuyer() throws Exception {
        System.out.println("[TEST] testHandleTransactionRequestValidBuyer");
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), 
            anyString(), any(byte[].class))).thenReturn("{\"success\":true}".getBytes());
        
        byte[] request = createSignedTransactionRequest("client43", 1002L, "client42", "client43", 
            "Copper", 3000, 500000, buyerKeyPair.getPrivate());
        
        byte[] response = serverOps.processRequest(request);
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("success") || responseStr.contains("stored"));
        
        System.out.println("[TEST] testHandleTransactionRequestValidBuyer passed");
    }

    // Verify authorization - only seller or buyer can submit (Security Requirement SR2)
    @Test
    public void testHandleTransactionRequestInvalidSource() throws Exception {
        System.out.println("[TEST] testHandleTransactionRequestInvalidSource");
        
        // Source is neither seller nor buyer - should be rejected (SR2)
        byte[] request = createSignedTransactionRequest("attacker", 1003L, "client42", "client43", 
            "Gold", 1000, 2000000, serverKeyPair.getPrivate());
        
        byte[] response = serverOps.processRequest(request);
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("error") || responseStr.contains("Access denied"));
        
        System.out.println("[TEST] testHandleTransactionRequestInvalidSource passed");
    }

    // Verify signature validation - source must sign with their own key
    @Test
    public void testHandleTransactionRequestInvalidSignature() throws Exception {
        System.out.println("[TEST] testHandleTransactionRequestInvalidSignature");
        
        // Seller submits but signs with wrong key
        byte[] request = createSignedTransactionRequest("client42", 1004L, "client42", "client43", 
            "Silver", 2000, 300000, buyerKeyPair.getPrivate()); // Wrong key!
        
        byte[] response = serverOps.processRequest(request);
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("error") || responseStr.contains("Invalid signature"));
        
        System.out.println("[TEST] testHandleTransactionRequestInvalidSignature passed");
    }

    // Verify seller can share transaction with third party (Security Requirement SR3)
    @Test
    public void testHandleShareRequestValid() throws Exception {
        System.out.println("[TEST] testHandleShareRequestValid");
        
        // Mock database to return transaction where client42 is seller
        String dbResponse = "{\"id\":1005,\"seller\":\"client42\",\"buyer\":\"client43\"}";
        apiCallsMock.when(() -> ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), 
            anyString(), any(byte[].class))).thenReturn(dbResponse.getBytes());
        
        // Create share request
        String shareData = "1005:client44:client42"; // transaction_id:share_with:source share request format
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(sellerKeyPair.getPrivate());
        sig.update(shareData.getBytes());
        String signature = Base64.getEncoder().encodeToString(sig.sign());
        
        String request = String.format(
            "{request_type:share, source:client42, transaction_id:1005, share_with:client44, signature:%s}",
            signature
        );
        
        byte[] response = serverOps.processRequest(request.getBytes());
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("success") || responseStr.contains("shared"));
        
        System.out.println("[TEST] testHandleShareRequestValid passed");
    }

    // Verify only seller or buyer can share a transaction, unauthorized sources rejected
    @Test
    public void testHandleShareRequestUnauthorized() throws Exception {
        System.out.println("[TEST] testHandleShareRequestUnauthorized");
        
        // Mock database to return transaction where client44 is NOT seller or buyer
        String dbResponse = "{\"id\":1006,\"seller\":\"client42\",\"buyer\":\"client43\"}";
        apiCallsMock.when(() -> ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), 
            anyString(), any(byte[].class))).thenReturn(dbResponse.getBytes());
        
        String shareData = "1006:client45:client44";
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(serverKeyPair.getPrivate());
        sig.update(shareData.getBytes());
        String signature = Base64.getEncoder().encodeToString(sig.sign());
        
        String request = String.format(
            "{request_type:share, source:client44, transaction_id:1006, share_with:client45, signature:%s}",
            signature
        );
        
        byte[] response = serverOps.processRequest(request.getBytes());
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("error") || responseStr.contains("Access denied"));
        
        System.out.println("[TEST] testHandleShareRequestUnauthorized passed");
    }

    // Verify getById request with access control, verify authorized users can retrieve transaction details (SR4)
    @Test
    public void testHandleGetByIdRequestWithAccess() throws Exception {
        System.out.println("[TEST] testHandleGetByIdRequestWithAccess");
        
        // Mock database responses
        String transactionResponse = "{\"id\":1007,\"timestamp\":1234567890,\"seller\":\"client42\",\"buyer\":\"client43\",\"product\":\"Platinum\",\"units\":100,\"amount\":500000,\"sellerSignature\":\"sig1\",\"buyerSignature\":\"sig2\"}";
        String sharesResponse = "[\"client42\",\"client43\"]";
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), 
            anyString(), any(byte[].class)))
            .thenReturn(transactionResponse.getBytes())
            .thenReturn(sharesResponse.getBytes());
        
        String request = "{request_type:getById, source:client42, transaction_id:1007}";
        
        byte[] response = serverOps.processRequest(request.getBytes());
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("client42") && responseStr.contains("Platinum"));
        assertFalse(responseStr.contains("error"));
        
        System.out.println("[TEST] testHandleGetByIdRequestWithAccess passed");
    }

    // Verify getById request access control - unauthorized users cannot retrieve transaction details (SR4)
    @Test
    public void testHandleGetByIdRequestWithoutAccess() throws Exception {
        System.out.println("[TEST] testHandleGetByIdRequestWithoutAccess");
        
        // Mock database responses - client44 is not in shares list
        String transactionResponse = "{\"id\":1008,\"seller\":\"client42\",\"buyer\":\"client43\"}";
        String sharesResponse = "[\"client42\",\"client43\"]";
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), 
            anyString(), any(byte[].class)))
            .thenReturn(transactionResponse.getBytes())
            .thenReturn(sharesResponse.getBytes());
        
        String request = "{request_type:getById, source:client44, transaction_id:1008}";
        
        byte[] response = serverOps.processRequest(request.getBytes());
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("error") || responseStr.contains("Access denied"));
        
        System.out.println("[TEST] testHandleGetByIdRequestWithoutAccess passed");
    }

    // Verify getAll request returns all transactions for the source, verify user can retrieve all their transactions (Security Requirement SR4)
    @Test
    public void testHandleGetAllRequest() throws Exception {
        System.out.println("[TEST] testHandleGetAllRequest");
        
        // Mock database response with multiple transactions
        String allTransactionsResponse = "[{\"id\":1009,\"timestamp\":1234567890,\"seller\":\"client42\",\"buyer\":\"client43\",\"product\":\"Zinc\",\"units\":200,\"amount\":100000,\"sellerSignature\":\"sig1\",\"buyerSignature\":\"sig2\"},{\"id\":1010,\"timestamp\":1234567891,\"seller\":\"client42\",\"buyer\":\"client44\",\"product\":\"Nickel\",\"units\":150,\"amount\":80000,\"sellerSignature\":\"sig3\",\"buyerSignature\":\"sig4\"}]";
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), 
            anyString(), any(byte[].class))).thenReturn(allTransactionsResponse.getBytes());
        
        String request = "{request_type:getAll, source:client42}";
        
        byte[] response = serverOps.processRequest(request.getBytes());
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("transactions"));
        assertTrue(responseStr.contains("Zinc") || responseStr.contains("Nickel"));
        
        System.out.println("[TEST] testHandleGetAllRequest passed");
    }

    // Verify getShares request returns all shares for a transaction, verify correct share records are returned (Security Requirement SR5)
    //  Verify user can see who has access to a transaction and when they were granted access
    @Test
    public void testHandleGetSharesRequest() throws Exception {
        System.out.println("[TEST] testHandleGetSharesRequest");
        
        // Mock database responses
        String transactionResponse = "{\"id\":1011,\"seller\":\"client42\",\"buyer\":\"client43\"}";
        String sharesListResponse = "[\"client42\",\"client43\",\"client44\"]";
        String shareRecordsResponse = "[{\"share\":\"client42\",\"sharedBy\":\"server\",\"timestamp\":1234567890,\"signature\":\"sig1\"},{\"share\":\"client43\",\"sharedBy\":\"server\",\"timestamp\":1234567890,\"signature\":\"sig2\"},{\"share\":\"client44\",\"sharedBy\":\"client42\",\"timestamp\":1234567900,\"signature\":\"sig3\"}]";
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), 
            anyString(), any(byte[].class)))
            .thenReturn(transactionResponse.getBytes())
            .thenReturn(sharesListResponse.getBytes())
            .thenReturn(shareRecordsResponse.getBytes());
        
        String request = "{request_type:getShares, source:client42, transaction_id:1011}";
        
        byte[] response = serverOps.processRequest(request.getBytes());
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("shares"));
        assertTrue(responseStr.contains("signature"));
        
        System.out.println("[TEST] testHandleGetSharesRequest passed");
    }

    // Verify getSharesBy request returns all transactions shared by a specific user, verify correct records are returned (Security Requirement SR5)
    @Test
    public void testHandleGetSharesByRequest() throws Exception {
        System.out.println("[TEST] testHandleGetSharesByRequest");
        
        // Mock database responses
        String sharesListResponse = "[\"client42\",\"client43\",\"client44\"]";
        String sharesByResponse = "[{\"share\":\"client44\",\"sharedBy\":\"client42\",\"timestamp\":1234567900,\"signature\":\"sig1\"}]";
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(anyString(), anyInt(), anyString(), anyInt(), 
            anyString(), any(byte[].class)))
            .thenReturn(sharesListResponse.getBytes())
            .thenReturn(sharesByResponse.getBytes());
        
        String request = "{request_type:getSharesBy, source:client42, transaction_id:1012, shared_by:client42}";
        
        byte[] response = serverOps.processRequest(request.getBytes());
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("shares"));
        assertTrue(responseStr.contains("client44") || responseStr.contains("client42"));
        
        System.out.println("[TEST] testHandleGetSharesByRequest passed");
    }

    // Verify server handles invalid request types gracefully
    @Test
    public void testHandleInvalidRequestType() throws Exception {
        System.out.println("[TEST] testHandleInvalidRequestType");
        
        String request = "{request_type:invalid_operation, source:client42}";
        
        byte[] response = serverOps.processRequest(request.getBytes());
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("error") || responseStr.contains("Unknown"));
        
        System.out.println("[TEST] testHandleInvalidRequestType passed");
    }

    // Verify server handles malformed requests gracefully (Security Requirement SR6)
    @Test
    public void testHandleMalformedRequest() throws Exception {
        System.out.println("[TEST] testHandleMalformedRequest");
        
        String request = "this is not valid json or request format";
        
        byte[] response = serverOps.processRequest(request.getBytes());
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("error"));
        
        System.out.println("[TEST] testHandleMalformedRequest passed");
    }

    // Verify transaction request missing required fields is rejected (Security Requirement SR6)
    @Test
    public void testTransactionMissingRequiredFields() throws Exception {
        System.out.println("[TEST] testTransactionMissingRequiredFields");
        
        // Transaction missing buyer field
        String request = "{request_type: transaction, source: client42}{\"id\":1013,\"seller\":\"client42\",\"product\":\"Gold\"}{signature:fakesig}";
        
        byte[] response = serverOps.processRequest(request.getBytes());
        
        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        assertTrue(responseStr.contains("error"));
        
        System.out.println("[TEST] testTransactionMissingRequiredFields passed");
    }
}
