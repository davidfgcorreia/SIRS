package com.chainofproduct.server;

import com.chainofproduct.utils.ApiCalls;

import org.junit.BeforeClass;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;


import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import org.mockito.MockedStatic;

public class ServerOperationsTest {
    private ServerOperations serverOps;
    private static KeyPair sellerKeyPair;
    private static KeyPair buyerKeyPair;
    private static KeyPair serverKeyPair;
    private MockedStatic<ApiCalls> apiCallsMock;

    @BeforeClass
    public static void setUp() throws Exception {
        System.out.println("[SETUP] Initializing ServerOperationsTest");
        
        // Generate test key pairs
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        sellerKeyPair = keyGen.generateKeyPair();
        buyerKeyPair = keyGen.generateKeyPair();
        serverKeyPair = keyGen.generateKeyPair();
        
        // Key pairs generated once for all tests; per-test mocks and ServerOperations instance
        // will be created in @Before to ensure deterministic mock behavior.
        
        System.out.println("[SETUP] ServerOperationsTest initialized");
    }

    @Before
    public void setUpTest() throws Exception {
        // Create per-test static mock for ApiCalls
        apiCallsMock = mockStatic(ApiCalls.class);
        // Simulate a simple in-memory database per test to make DB behavior deterministic.
        final java.util.Map<Long, byte[]> txStore = new java.util.HashMap<>();
        final java.util.Map<Long, java.util.List<byte[]>> shareRecords = new java.util.HashMap<>();
        final com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();

        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), any(), anyInt(), any(), any(byte[].class)))
            .thenAnswer(invocation -> {
                Object[] args = invocation.getArguments();
                byte[] reqBytes = (byte[]) args[5];
                try {
                    com.fasterxml.jackson.databind.JsonNode node = mapper.readTree(reqBytes);
                    int sql = node.has("sql") ? node.get("sql").asInt() : -1;
                    switch (sql) {
                        case 0: // insert transaction
                            long id = node.get("id").asLong();
                            txStore.put(id, reqBytes);
                            // create default share records for seller/buyer
                            java.util.List<byte[]> list = new java.util.ArrayList<>();
                            list.add(mapper.writeValueAsBytes(java.util.Collections.singletonMap("share", node.get("seller").asText())));
                            list.add(mapper.writeValueAsBytes(java.util.Collections.singletonMap("share", node.get("buyer").asText())));
                            shareRecords.put(id, list);
                            return mapper.writeValueAsBytes(java.util.Collections.singletonMap("success", true));
                        case 1: // add share
                            long tid = node.get("transactionId").asLong();
                            shareRecords.computeIfAbsent(tid, k -> new java.util.ArrayList<>()).add(reqBytes);
                            return mapper.writeValueAsBytes(java.util.Collections.singletonMap("success", true));
                        case 5: // get transaction by id
                            long qid = node.get("id").asLong();
                            byte[] tx = txStore.get(qid);
                            if (tx == null) return null;
                            // For getTransactionById, return a minimal JSON with seller/buyer
                            com.fasterxml.jackson.databind.node.ObjectNode minimal = mapper.createObjectNode();
                            com.fasterxml.jackson.databind.JsonNode stored = mapper.readTree(tx);
                            minimal.put("id", qid);
                            minimal.put("seller", stored.has("seller") ? stored.get("seller").asText() : "client42");
                            minimal.put("buyer", stored.has("buyer") ? stored.get("buyer").asText() : "client43");
                            minimal.put("timestamp", stored.has("timestamp") ? stored.get("timestamp").asLong() : System.currentTimeMillis());
                            minimal.put("sellerSignature", stored.has("sellerSignature") ? stored.get("sellerSignature").asText() : "");
                            minimal.put("buyerSignature", stored.has("buyerSignature") ? stored.get("buyerSignature").asText() : "");
                            return mapper.writeValueAsBytes(minimal);
                        case 2: // get shares list
                            long sid = node.get("transactionId").asLong();
                            java.util.List<byte[]> recs = shareRecords.get(sid);
                            if (recs == null) return mapper.writeValueAsBytes(new String[]{});
                            // return list of share names
                            java.util.List<String> names = new java.util.ArrayList<>();
                            for (byte[] b : recs) {
                                try {
                                    com.fasterxml.jackson.databind.JsonNode n = mapper.readTree(b);
                                    if (n.has("share")) names.add(n.get("share").asText());
                                } catch (Exception ex) {
                                    // try parse different shape
                                    names.add(new String(b, java.nio.charset.StandardCharsets.UTF_8));
                                }
                            }
                            return mapper.writeValueAsBytes(names);
                        case 9: // get share records
                        case 10: // get share records by
                            long trid = node.get("transactionId").asLong();
                            java.util.List<byte[]> records = shareRecords.get(trid);
                            if (records == null) return mapper.writeValueAsBytes(new String[]{});
                            // return raw records stored
                            com.fasterxml.jackson.databind.node.ArrayNode arr = mapper.createArrayNode();
                            for (byte[] b : records) {
                                try { arr.add(mapper.readTree(b)); } catch (Exception ex) { arr.add(new String(b, java.nio.charset.StandardCharsets.UTF_8)); }
                            }
                            return mapper.writeValueAsBytes(arr);
                        case 11: // getAllTransactionsWithShares
                            // return all transactions in txStore as array
                            com.fasterxml.jackson.databind.node.ArrayNode all = mapper.createArrayNode();
                            for (byte[] b : txStore.values()) {
                                try { all.add(mapper.readTree(b)); } catch (Exception ex) { }
                            }
                            return mapper.writeValueAsBytes(all);
                        default:
                            return mapper.writeValueAsBytes(java.util.Collections.singletonMap("success", true));
                    }
                } catch (Exception e) {
                    return "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                }
            });

        // Create a fresh ServerOperations instance for each test overriding keystore loaders
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
    }

    @After
    public void tearDown() {
        // Reset mocks between tests
        if (apiCallsMock != null) {
            apiCallsMock.clearInvocations();
            apiCallsMock.close();
            apiCallsMock = null;
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
        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), anyString(), anyInt(), 
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
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), anyString(), anyInt(), 
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
        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), anyString(), anyInt(), 
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
        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), anyString(), anyInt(), 
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
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), anyString(), anyInt(), 
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
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), anyString(), anyInt(), 
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
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), anyString(), anyInt(), 
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
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), anyString(), anyInt(), 
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
        
        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), anyString(), anyInt(), 
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

    // Verify server accepts payloads that include two concatenated signatures (seller + buyer)
    @Test
    public void testHandleTransactionRequestWithTwoSignatures() throws Exception {
        System.out.println("[TEST] testHandleTransactionRequestWithTwoSignatures");

        // DB mock behavior provided by test setup; no override needed here.

        // Build transaction JSON
        String transactionJson = String.format(
            "{\"id\":%d,\"timestamp\":%d,\"seller\":\"%s\",\"buyer\":\"%s\",\"product\":\"%s\",\"units\":%d,\"amount\":%d}",
            2001L, System.currentTimeMillis(), "client42", "client43", "TestMaterial", 10L, 1000L
        );

        byte[] transactionBytes = transactionJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // Seller signs
        Signature sellerSig = Signature.getInstance("SHA256withRSA");
        sellerSig.initSign(sellerKeyPair.getPrivate());
        sellerSig.update(transactionBytes);
        String sellerSignatureB64 = Base64.getEncoder().encodeToString(sellerSig.sign());

        // Buyer signs
        Signature buyerSig = Signature.getInstance("SHA256withRSA");
        buyerSig.initSign(buyerKeyPair.getPrivate());
        buyerSig.update(transactionBytes);
        String buyerSignatureB64 = Base64.getEncoder().encodeToString(buyerSig.sign());

        // Build header and attach both signatures: header + transaction + {signature:SELLER}{signature:BUYER}
        String header = String.format("{request_type: transaction, source: %s}", "client42");
        String sellerSigPart = String.format("{signature:%s}", sellerSignatureB64);
        String buyerSigPart = String.format("{signature:%s}", buyerSignatureB64);

        byte[] headerBytes = header.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] sellerSigBytes = sellerSigPart.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] buyerSigBytes = buyerSigPart.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        byte[] fullRequest = new byte[headerBytes.length + transactionBytes.length + sellerSigBytes.length + buyerSigBytes.length];
        System.arraycopy(headerBytes, 0, fullRequest, 0, headerBytes.length);
        System.arraycopy(transactionBytes, 0, fullRequest, headerBytes.length, transactionBytes.length);
        System.arraycopy(sellerSigBytes, 0, fullRequest, headerBytes.length + transactionBytes.length, sellerSigBytes.length);
        System.arraycopy(buyerSigBytes, 0, fullRequest, headerBytes.length + transactionBytes.length + sellerSigBytes.length, buyerSigBytes.length);

        byte[] response = serverOps.processRequest(fullRequest);

        assertNotNull(response);
        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Response: " + responseStr);
        // Expect success because seller (source) provided a valid signature among the two
        assertTrue(responseStr.contains("success") || responseStr.contains("stored"));

        System.out.println("[TEST] testHandleTransactionRequestWithTwoSignatures passed");
    }

    // Verify duplicate transactions are rejected to prevent replay attacks
    @Test
    public void testDuplicateTransactionRejected() throws Exception {
        System.out.println("[TEST] testDuplicateTransactionRejected");

        // DB mock behavior provided by test setup; initial DB is empty so first submission will insert.

        byte[] request = createSignedTransactionRequest("client42", 3001L, "client42", "client43",
            "Steel", 50, 5000, sellerKeyPair.getPrivate());

        // First submission should succeed
        byte[] response1 = serverOps.processRequest(request);
        assertNotNull(response1);
        String r1 = new String(response1, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] First response: " + r1);
        assertTrue(r1.contains("success") || r1.contains("stored"));

        // Reconfigure DB stub: next check (sql=5) should return existing transaction
        apiCallsMock.when(() -> ApiCalls.actAsSender(any(), anyInt(), anyString(), anyInt(),
            anyString(), any(byte[].class)))
            .thenReturn("{\"id\":3001,\"seller\":\"client42\",\"buyer\":\"client43\"}".getBytes());

        // Second submission (same id) should be rejected as duplicate
        byte[] response2 = serverOps.processRequest(request);
        assertNotNull(response2);
        String r2 = new String(response2, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[TEST] Second response: " + r2);
        assertTrue(r2.contains("error") || r2.contains("already") || r2.contains("exists"));

        System.out.println("[TEST] testDuplicateTransactionRejected passed");
    }

    // Verify server parsing extracts exactly the same transaction bytes that the client signed
    @Test
    public void testServerParsesExactTransactionBytes() throws Exception {
        System.out.println("[TEST] testServerParsesExactTransactionBytes");

        // Use deterministic transaction fields
        long id = 4001L;
        long timestamp = System.currentTimeMillis();
        String seller = "client42";
        String buyer = "client43";
        String product = "Graphite";
        long units = 123L;
        long amount = 456789L;

        String transactionJson = String.format(
            "{\"id\":%d,\"timestamp\":%d,\"seller\":\"%s\",\"buyer\":\"%s\",\"product\":\"%s\",\"units\":%d,\"amount\":%d}",
            id, timestamp, seller, buyer, product, units, amount
        );

        byte[] transactionBytes = transactionJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // Seller signs
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(sellerKeyPair.getPrivate());
        sig.update(transactionBytes);
        String sellerSignatureB64 = Base64.getEncoder().encodeToString(sig.sign());

        // Build full request: header + transaction + signature
        String header = String.format("{request_type: transaction, source: %s}", seller);
        String sellerSigPart = String.format("{signature:%s}", sellerSignatureB64);

        byte[] headerBytes = header.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] sellerSigBytes = sellerSigPart.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        byte[] fullRequest = new byte[headerBytes.length + transactionBytes.length + sellerSigBytes.length];
        System.arraycopy(headerBytes, 0, fullRequest, 0, headerBytes.length);
        System.arraycopy(transactionBytes, 0, fullRequest, headerBytes.length, transactionBytes.length);
        System.arraycopy(sellerSigBytes, 0, fullRequest, headerBytes.length + transactionBytes.length, sellerSigBytes.length);

        byte[] response = serverOps.processRequest(fullRequest);
        assertNotNull(response);

        // Get server-parsed bytes and compare
        byte[] parsed = serverOps.getLastParsedTransactionBytes();
        assertNotNull("Server did not store parsed transaction bytes", parsed);
        assertArrayEquals("Parsed transaction bytes differ from original", transactionBytes, parsed);

        String responseStr = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(responseStr.contains("success") || responseStr.contains("stored"));

        System.out.println("[TEST] testServerParsesExactTransactionBytes passed");
    }
}
