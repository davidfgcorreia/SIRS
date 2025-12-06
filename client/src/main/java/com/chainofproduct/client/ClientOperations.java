package com.chainofproduct.client;

import java.util.concurrent.BlockingQueue;

import com.chainofproduct.utils.Request;

public class ClientOperations {
    private final BlockingQueue<Request> sendQueue;
    private final Object sendLock;
    private final String clientName;
    private final String entityType;
    private final int clientNum;
    private final String receiverEntity;
    private final String serverHost;
    private final int serverPort;

    public ClientOperations(BlockingQueue<Request> sendQueue, Object sendLock, String clientName) {
        this.sendQueue = sendQueue;
        this.sendLock = sendLock;
        this.clientName = clientName;
        this.entityType = "client";
        this.clientNum = parseClientNum(clientName);
        this.receiverEntity = "server";
        com.chainofproduct.utils.ResolveDestinations.DestinationInfo destInfo = null;
        try {
            destInfo = com.chainofproduct.utils.ResolveDestinations.resolve("server");
        } catch (Exception e) {
            System.err.println("Failed to load server info from localizationinfo/serverinfo.json: " + e.getMessage());
        }
        this.serverHost = destInfo.ip;
        this.serverPort = destInfo.port;
        
        


        // Ensure server cert/pubkey is present (exchange only once)
        try {
            // 1. Generate/load EC keypair for this client
            String ecKeystorePath = this.clientName + "-ec-keystore.p12";
            String ecAlias = this.clientName + "-ec";
            String ecPassword = "changeit";
            java.security.KeyPair ecKeyPair;
            java.io.File ecKeystoreFile = new java.io.File(ecKeystorePath);
            if (ecKeystoreFile.exists()) {
                try {
                    java.security.PrivateKey priv = com.chainofproduct.utils.KeyTransmission.getMyECPrivateKey(ecKeystorePath, ecAlias);
                    java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(ecKeystorePath)) {
                        ks.load(fis, ecPassword.toCharArray());
                    }
                    java.security.PublicKey pub = ks.getCertificate(ecAlias).getPublicKey();
                    ecKeyPair = new java.security.KeyPair(pub, priv);
                } catch (Exception e) {
                    System.err.println("Error loading EC keypair, regenerating: " + e.getMessage());
                    ecKeyPair = com.chainofproduct.utils.KeyTransmission.generateECKeyPairAndStore(ecAlias, ecKeystorePath, ecPassword);
                }
            } else {
                ecKeyPair = com.chainofproduct.utils.KeyTransmission.generateECKeyPairAndStore(ecAlias, ecKeystorePath, ecPassword);
            }

            // 2. Load this client's RSA public key and certificate
            String myKeystorePath = this.clientName + "-keystore.p12";
            String myKeystorePassword = "changeit";
            java.security.KeyStore myKeystore = com.chainofproduct.utils.Cerificates.getKeystore(this.clientName, myKeystorePassword);
            if (myKeystore == null) {
                throw new java.io.FileNotFoundException("Keystore not found: " + myKeystorePath);
            }
            java.security.cert.Certificate myCert = myKeystore.getCertificate(this.clientName);
            if (myCert == null) {
                throw new java.security.cert.CertificateException("No certificate found for alias: " + this.clientName);
            }
            java.security.PublicKey myRSAPubKey = myCert.getPublicKey();

            // 3. Call sendRSAKeyAndCertWithECDH to the server
            com.chainofproduct.utils.KeyTransmission.sendRSAKeyAndCertWithECDH(
                this.clientName, // storePrefix
                this.clientName, // myAlias
                this.receiverEntity, // peerAlias (server)
                this.serverHost,
                (destInfo != null && destInfo.certPort != 0) ? destInfo.certPort : (this.serverPort + 1000), // Use certPort if available, else fallback
                ecKeyPair,
                myRSAPubKey,
                (java.security.cert.X509Certificate) myCert
            );
        } catch (Exception e) {
            System.err.println("Certificate verification/exchange with server failed: " + e.getMessage());
        }
    }

    
    // Enqueue a transaction send request (Type 1)
    public void sendtrsaction(String dataFile, String destination) {
        // Resolve destination info
        com.chainofproduct.utils.ResolveDestinations.DestinationInfo destInfo = com.chainofproduct.utils.ResolveDestinations.resolve(destination);
        String partnerHost = destInfo != null ? destInfo.ip : null;
        int partnerPort = destInfo != null ? destInfo.signaturePort : 0;
        // Ensure receiver cert/pubkey is present
        try {
            com.chainofproduct.utils.Cerificates.verifyCertificaAndObtain(this.clientName, destination, partnerHost, partnerPort);
        } catch (Exception e) {
            System.err.println("Certificate verification/exchange failed: " + e.getMessage());
            return;
        }
        String payload; // Will be set after isSeller/isBuyer are determined
        byte[] fileBytes = null;
        java.nio.file.Path path;
        try {
            path = java.nio.file.Paths.get(dataFile);
            fileBytes = java.nio.file.Files.readAllBytes(path);
        } catch (Exception e) {
            System.err.println("Failed to read dataFile as bytes: " + e.getMessage());
            return;
        }

        // Parse JSON to get seller and buyer
        String fileStr = new String(fileBytes, java.nio.charset.StandardCharsets.UTF_8);
        int jsonEnd = fileStr.indexOf('}') + 1;
        if (jsonEnd <= 0) {
            System.err.println("Invalid transaction file: missing JSON object");
            return;
        }
        String jsonPart = fileStr.substring(0, jsonEnd);
        String seller = extractJsonStringField(jsonPart, "seller");
        String buyer = extractJsonStringField(jsonPart, "buyer");
        if (seller == null || buyer == null) {
            System.err.println("Transaction JSON missing seller or buyer field");
            return;
        }
        boolean isSeller = this.clientName.equalsIgnoreCase(seller);
        boolean isBuyer = this.clientName.equalsIgnoreCase(buyer);
        // Now that isSeller and isBuyer are defined, set the payload with role
        String role = isSeller ? "seller" : (isBuyer ? "buyer" : "unknown");
        payload = "{request_type: transaction, source: " + this.clientName + ", destination: " + destination + ", role: " + role + "}";
        System.out.println("[sendtrsaction] BEGIN");
        System.out.println("[sendtrsaction] dataFile: " + dataFile);
        System.out.println("[sendtrsaction] destination: " + destination);
        System.out.println("[sendtrsaction] BEGIN");
        System.out.println("[sendtrsaction] dataFile: " + dataFile);
        System.out.println("[sendtrsaction] destination: " + destination);
        if (!isSeller && !isBuyer) {
            System.err.println("Client is neither seller nor buyer, cannot send transaction");
            System.out.println("[sendtrsaction] partnerHost: " + partnerHost + ", partnerPort: " + partnerPort);
            System.out.println("[sendtrsaction] partnerHost: " + partnerHost + ", partnerPort: " + partnerPort);
            return;
        }

        // Check if file is already double signed: prefer filename, fallback to length/signature check
        boolean alreadySigned = false;
                System.out.println("[sendtrsaction] Read fileBytes, length: " + (fileBytes != null ? fileBytes.length : -1));
        if (dataFile.endsWith("_signed.bin")) {
                System.out.println("[sendtrsaction] Read fileBytes, length: " + (fileBytes != null ? fileBytes.length : -1));
            alreadySigned = true;
        } else {
            int sigLen = 344; // typical RSA signature length in Base64
            System.out.println("[sendtrsaction] fileStr: " + fileStr);
            if (fileBytes.length > sigLen * 2) {
            System.out.println("[sendtrsaction] jsonEnd: " + jsonEnd);
                String sellerSig = fileStr.substring(fileStr.length() - sigLen * 2, fileStr.length() - sigLen);
                String buyerSig = fileStr.substring(fileStr.length() - sigLen);
            System.out.println("[sendtrsaction] fileStr: " + fileStr);
                if (sellerSig.matches("[A-Za-z0-9+/=]{344}") && buyerSig.matches("[A-Za-z0-9+/=]{344}")) {
            System.out.println("[sendtrsaction] jsonEnd: " + jsonEnd);
            System.out.println("[sendtrsaction] jsonPart: " + jsonPart);
                    alreadySigned = true;
                }
            System.out.println("[sendtrsaction] seller: " + seller + ", buyer: " + buyer);
            }
        }
                System.err.println("[sendtrsaction] seller or buyer is null");
        byte[] toSend;
            System.out.println("[sendtrsaction] jsonPart: " + jsonPart);
        if (alreadySigned) {
            // File is already double signed, send as is
            System.out.println("[sendtrsaction] isSeller: " + isSeller + ", isBuyer: " + isBuyer);
            System.out.println("[sendtrsaction] seller: " + seller + ", buyer: " + buyer);
            toSend = fileBytes;
                System.err.println("[sendtrsaction] clientName: " + this.clientName);
        } else {
                System.err.println("[sendtrsaction] seller or buyer is null");
            // Not signed, obtain signatures
            String partnerName = destination;
            String[] signatures = obtainDoubleSignature(fileBytes, partnerHost, partnerPort, partnerName, isSeller);
            if (signatures == null || signatures.length != 2) {
                System.out.println("[sendtrsaction] File ends with _signed.bin, alreadySigned = true");
            System.out.println("[sendtrsaction] isSeller: " + isSeller + ", isBuyer: " + isBuyer);
                System.err.println("Failed to obtain double signature");
                return;
            }
                System.out.println("[sendtrsaction] my: " + signatures[0]);
                System.out.println("[sendtrsaction] partner: " + signatures[1]);
            // Concatenate file + mySignature + partnerSignature
            byte[] mySigBytes = signatures[isSeller ? 0 : 1].getBytes(java.nio.charset.StandardCharsets.UTF_8);
            System.out.println("[sendtrsaction] Both signatures match expected format, alreadySigned = true");
            byte[] partnerSigBytes = signatures[isSeller ? 1 : 0].getBytes(java.nio.charset.StandardCharsets.UTF_8);
            toSend = new byte[fileBytes.length + mySigBytes.length + partnerSigBytes.length];
            System.arraycopy(fileBytes, 0, toSend, 0, fileBytes.length);
                System.out.println("[sendtrsaction] File ends with _signed.bin, alreadySigned = true");
            System.arraycopy(mySigBytes, 0, toSend, fileBytes.length, mySigBytes.length);
            System.arraycopy(partnerSigBytes, 0, toSend, fileBytes.length + mySigBytes.length, partnerSigBytes.length);
                System.out.println("[sendtrsaction] Sending already double signed file, length: " + toSend.length);

            // Store signed file in same directory as original, named <transaction_id>_signed.json
                System.out.println("[sendtrsaction] Obtaining double signature for partnerName: " + partnerName);
            try {
                System.out.println("[sendtrsaction] obtainDoubleSignature returned: " + (signatures == null ? "null" : java.util.Arrays.toString(signatures)));
                    System.out.println("[sendtrsaction] my: " + signatures[0]);
                    System.out.println("[sendtrsaction] partner: " + signatures[1]);
                    System.err.println("[sendtrsaction] signatures null or length != 2");
                java.nio.file.Path parentDir = path.getParent();
                // Extract transaction_id from JSON
                        System.out.println("[sendtrsaction] Both signatures match expected format, alreadySigned = true");
                String transactionId = extractJsonStringField(jsonPart, "transaction_id");
                System.out.println("[sendtrsaction] mySigBytes length: " + mySigBytes.length);
                System.out.println("[sendtrsaction] partnerSigBytes length: " + partnerSigBytes.length);
                String signedFileName = transactionId + "_signed.bin";
                java.nio.file.Path signedPath = parentDir.resolve(signedFileName);
                java.nio.file.Files.write(signedPath, toSend);
                System.out.println("Signed transaction file written to: " + signedPath);
                System.out.println("[sendtrsaction] toSend length: " + toSend.length);
            } catch (Exception e) {
                System.out.println("[sendtrsaction] Sending already double signed file, length: " + toSend.length);
                System.err.println("Failed to write signed transaction file: " + e.getMessage());
            }
                System.out.println("[sendtrsaction] Obtaining double signature for partnerName: " + partnerName);
        }

        byte[] payloadBytes = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        System.err.println("[sendtrsaction] signatures null or length != 2");
        byte[] combined = new byte[payloadBytes.length + toSend.length];
        System.arraycopy(payloadBytes, 0, combined, 0, payloadBytes.length);
        System.arraycopy(toSend, 0, combined, payloadBytes.length, toSend.length);
        System.out.println("[sendtrsaction] payloadBytes length: " + payloadBytes.length);
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum, // int, matches Request constructor
            this.receiverEntity,
            combined
        );
            System.out.println("[sendtrsaction] Request created: host=" + this.serverHost + ", port=" + this.serverPort + ", entityType=" + this.entityType + ", clientNum=" + this.clientNum + ", receiverEntity=" + this.receiverEntity + ", combined.length=" + combined.length);
        enqueueRequest(req);
            System.out.println("[sendtrsaction] END");
        System.out.println("Enqueued transaction send request for " + destination);
    }

    // Enqueue a getById request (Type 3)
    public void gettransactionById(long id) {
        String payload = "{request_type:getById, servername: " + this.clientName +  ", trasaction_id: " + id + "}";
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        enqueueRequest(req);
        System.out.println("Enqueued getById request for id=" + id);
    }

    // Enqueue a getAll request (Type 4)
    public void getAll() {
        System.out.println("[sendtrsaction] Request created: host=" + this.serverHost + ", port=" + this.serverPort + ", entityType=" + this.entityType + ", clientNum=" + this.clientNum + ", receiverEntity=" + this.receiverEntity );
        String payload = "{request_type:getAll, servername: " + this.clientName + "}";
        System.out.println("[sendtrsaction] END");
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        enqueueRequest(req);
        System.out.println("Enqueued getAll request");
    }

    // Enqueue a getShares request (Type 5)
    public void getShares(long tid) {
        String payload = "{request_type:getShares, servername: " + this.clientName + ", transaction_id: " + tid + "}";
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        enqueueRequest(req);
        System.out.println("Enqueued getShares request for tid=" + tid);
    }

    // Enqueue a getSharesBy request (Type 6)
    public void getSharesBy(long tid, String sharedBy) {
        String payload = "{request_type:getSharesBy, servername: " + this.clientName + ", transaction_id: " + tid + ", shared_by: " + sharedBy + "}";
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        enqueueRequest(req);
        System.out.println("Enqueued getSharesBy request for tid=" + tid + ", sharedBy=" + sharedBy);
    }

        // Enqueue a getRecentTransactions request (Type 7)
    public void getRecentTransactionsSince(long sinceTimestamp) {
        String payload = "{request_type:getRecentTransactions, servername: " + this.clientName + ", since: " + sinceTimestamp + "}";
        Request req = new Request(
            this.serverHost,
            this.serverPort,
            this.entityType,
            this.clientNum,
            this.receiverEntity,
            payload.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        enqueueRequest(req);
        System.out.println("Enqueued getRecentTransactions request since timestamp=" + sinceTimestamp);
    }


    public String[] obtainDoubleSignature(byte[] transactionData, String PartnerHost, int PartnerPort,String PartnerName, boolean isSeller) {
        String mySignature = signTransactionData(transactionData);
        if (mySignature == null) {
            System.err.println("Failed to create seller signature");
            return null;
        }
        
        System.out.println("Seller (" + this.clientName + ") signed transaction");
            
        // Request buyer's signature
        // Add role field to signatureRequest payload
        String role = isSeller ? "seller" : "buyer";
        String payload = "{request_type:signatureRequest, source: " + this.clientName + ", mySignature: " + mySignature + ", role: " + role + "}";
        byte[] payloadBytes = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] combined = new byte[payloadBytes.length + transactionData.length];
        System.arraycopy(payloadBytes, 0, combined, 0, payloadBytes.length);
        System.arraycopy(transactionData, 0, combined, payloadBytes.length, transactionData.length);
        
        byte[] responseBytes;
        try{
            responseBytes = com.chainofproduct.utils.ApiCalls.actAsSender(
                PartnerHost, PartnerPort, this.entityType, this.clientNum, PartnerName, combined
            );
        }
        catch (Exception e) {
            System.err.println("Double signature error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
        
        if (responseBytes == null) {
            System.err.println("Failed to get buyer signature: no response");
            return null;
        }
        
        String response = new String(responseBytes, java.nio.charset.StandardCharsets.UTF_8);
        String partnerSignature = extractFieldValue(response, "signature");
        if (partnerSignature == null) {
            System.err.println("Failed to get buyer signature: no signature in response");
            return null;
        }
        
        System.out.println("Successfully obtained double signature");
            
        return new String[]{mySignature, partnerSignature};

            

    }
    
    
    /**
     * Signs transaction data with this client's private key.
     * 
     * @param transactionData The transaction data to sign
     * @return The signature in Base64 format, or null if signing failed
     */
    protected String signTransactionData(byte[] transactionData) {
        try {
            java.security.PrivateKey myPrivateKey = loadPrivateKeyFromKeystore(
                "client" + this.clientNum + "-keystore.p12",
                "client" + this.clientNum,
                "changeit"
            );
            
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] dataHash = digest.digest(transactionData);
            
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
            sig.initSign(myPrivateKey);
            sig.update(dataHash);
            byte[] signatureBytes = sig.sign();
            
            String signatureB64 = java.util.Base64.getEncoder().encodeToString(signatureBytes);
            System.out.println("Successfully signed transaction data as " + this.clientName);
            return signatureB64;
            
        } catch (Exception e) {
            System.err.println("Signing error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Handle an incoming signature request.
     * 
     * @param requestBytes The complete request bytes
     * @return Response bytes containing the signature, or null if failed
     */
    public byte[] handleSignatureRequest(byte[] requestBytes) {
        try {
            String requestStr = new String(requestBytes, java.nio.charset.StandardCharsets.UTF_8);
            String sourceName = extractFieldValue(requestStr, "source");
            if (sourceName == null) {
                System.err.println("handleSignatureRequest: Missing source");
                return null;
            }
            int payloadEnd = requestStr.indexOf('}') + 1;
            if (payloadEnd >= requestBytes.length) {
                System.err.println("handleSignatureRequest: No transaction data in request");
                return null;
            }
            byte[] transactionData = new byte[requestBytes.length - payloadEnd];
            System.arraycopy(requestBytes, payloadEnd, transactionData, 0, transactionData.length);
            String mySignature = signTransactionData(transactionData);
            if (mySignature == null) {
                System.err.println("handleSignatureRequest: Failed to sign transaction");
                return null;
            }

            // Try to extract the transaction_id from the transactionData (assume it's JSON)
            String txJson = new String(transactionData, java.nio.charset.StandardCharsets.UTF_8);
            int jsonEnd = txJson.indexOf('}') + 1;
            String jsonPart = jsonEnd > 0 ? txJson.substring(0, jsonEnd) : txJson;
            String transactionId = extractJsonStringField(jsonPart, "transaction_id");
            if (transactionId == null) transactionId = "unknown";

            // Formulate the double-signed file: transactionData + source signature + my signature
            // The source's signature is in the request (mySignature param), so extract it
            String sourceSignature = extractFieldValue(requestStr, "mySignature");
            if (sourceSignature == null) sourceSignature = "";
            // Compose the signed file: transactionData + sourceSignature + mySignature
            byte[] sourceSigBytes = sourceSignature.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] mySigBytes = mySignature.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] signedFile = new byte[transactionData.length + sourceSigBytes.length + mySigBytes.length];
            System.arraycopy(transactionData, 0, signedFile, 0, transactionData.length);
            System.arraycopy(sourceSigBytes, 0, signedFile, transactionData.length, sourceSigBytes.length);
            System.arraycopy(mySigBytes, 0, signedFile, transactionData.length + sourceSigBytes.length, mySigBytes.length);

            // Store the signed file in the current directory as <transaction_id>_signed.bin
            try {
                java.nio.file.Path signedPath = java.nio.file.Paths.get(transactionId + "_signed.bin");
                java.nio.file.Files.write(signedPath, signedFile);
                System.out.println("[handleSignatureRequest] Signed transaction file written to: " + signedPath);
            } catch (Exception e) {
                System.err.println("[handleSignatureRequest] Failed to write signed transaction file: " + e.getMessage());
            }

            String response = "{signature: " + mySignature + "}";
            return response.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("Error handling signature request: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    // Helper to extract a field value from JSON-like string (handles with/without quotes)
    private String extractFieldValue(String str, String field) {
        String key = field + ":";
        int idx = str.indexOf(key);
        if (idx == -1) return null;
        int start = idx + key.length();
        int end = str.indexOf(',', start);
        if (end == -1) end = str.indexOf('}', start);
        if (end == -1) return null;
        String value = str.substring(start, end).trim();
        // Remove possible quotes or spaces
        value = value.replaceAll("[\"{}\\s]", "");
        return value;
    }


    // Helper to enqueue and notify send manager
    private void enqueueRequest(Request req) {
        try {
            sendQueue.put(req);
            synchronized (sendLock) {
                sendLock.notifyAll();
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            System.err.println("enqueueRequest interrupted: " + ie.getMessage());
        }
    }

    /**
     * Verifies if a received file was not tampered with, using only this client's public key.
     * Determines role (seller/buyer) by parsing the JSON and comparing clientName.
     * Expects decryptedBytes in the format:
     *   {request_type:transaction, destination:...}<json file> <seller_signature> <buyer_signature>
     * Returns true if the relevant signature is valid for the file, false otherwise.
     */
    public boolean verifyFileIntegrity(String dataFilePath) {
        try {
            // Read the file bytes
            java.nio.file.Path path = java.nio.file.Paths.get(dataFilePath);
            byte[] completfileBytes = java.nio.file.Files.readAllBytes(path);

            // 1. Extract payload, file, and signatures
            String asString = new String(completfileBytes, java.nio.charset.StandardCharsets.UTF_8);
            int payloadEnd = asString.indexOf('}') + 1;
            if (payloadEnd <= 0) return false;
            int sigLen = 344;
            int buyerSigStart = completfileBytes.length - sigLen;
            int sellerSigStart = buyerSigStart - sigLen;
            if (sellerSigStart <= payloadEnd) return false;
            byte[] fileBytes = java.util.Arrays.copyOfRange(completfileBytes, payloadEnd, sellerSigStart);
            String sellerSigB64 = new String(java.util.Arrays.copyOfRange(completfileBytes, sellerSigStart, buyerSigStart), java.nio.charset.StandardCharsets.UTF_8);
            String buyerSigB64 = new String(java.util.Arrays.copyOfRange(completfileBytes, buyerSigStart, completfileBytes.length), java.nio.charset.StandardCharsets.UTF_8);
            // 2. Parse the JSON to determine role (manual string extraction)
            String jsonString = new String(fileBytes, java.nio.charset.StandardCharsets.UTF_8);
            int jsonEnd = jsonString.indexOf('}') + 1;
            if (jsonEnd <= 0) return false;
            String jsonPart = jsonString.substring(0, jsonEnd);
            String role = null;
            String seller = extractJsonStringField(jsonPart, "seller");
            String buyer = extractJsonStringField(jsonPart, "buyer");
            if (seller == null) seller = "";
            if (buyer == null) buyer = "";
            if (clientName.equalsIgnoreCase(seller)) {
                role = "seller";
            } else if (clientName.equalsIgnoreCase(buyer)) {
                role = "buyer";
            } else {
                System.err.println("verifyFileIntegrity: clientName does not match seller or buyer");
                return false;
            }

            // 3. Compute hash of the file
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] fileHash = digest.digest(fileBytes);

            // 4. Load my public key from PKCS12 truststore-pubkeys
            java.security.PublicKey myPubKey = loadPublicKeyFromTruststore("keys/client-truststore-pubkeys.p12", this.clientName, "changeit");

            // 5. Verify the relevant signature
            if ("seller".equalsIgnoreCase(role)) {
                return verifySignature(fileHash, sellerSigB64, myPubKey);
            } else if ("buyer".equalsIgnoreCase(role)) {
                return verifySignature(fileHash, buyerSigB64, myPubKey);
            } else {
                System.err.println("verifyFileIntegrity: unknown role '" + role + "'");
                return false;
            }
        } catch (Exception e) {
            System.err.println("verifyFileIntegrity error: " + e.getMessage());
            return false;
        }
    }


    // Helper to load a public key from PKCS12 truststore-pubkeys
    protected java.security.PublicKey loadPublicKeyFromTruststore(String truststorePath, String alias, String password) throws Exception {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(truststorePath)) {
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            ks.load(fis, password.toCharArray());
            java.security.cert.Certificate cert = ks.getCertificate(alias);
            if (cert == null) {
                throw new java.security.KeyStoreException("No certificate found for alias: " + alias);
            }
            return cert.getPublicKey();
        }
    }

    // Helper to load a private key from PKCS12 keystore
    private java.security.PrivateKey loadPrivateKeyFromKeystore(String keystorePath, String alias, String password) throws Exception {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            ks.load(fis, password.toCharArray());
            java.security.Key key = ks.getKey(alias, password.toCharArray());
            if (key == null || !(key instanceof java.security.PrivateKey)) {
                throw new java.security.KeyStoreException("No private key found for alias: " + alias);
            }
            return (java.security.PrivateKey) key;
        }
    }

    // Helper to verify a signature
    private boolean verifySignature(byte[] data, String signatureB64, java.security.PublicKey pubKey) throws Exception {
        byte[] sigBytes = java.util.Base64.getDecoder().decode(signatureB64);
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(data);
        return sig.verify(sigBytes);
    }

    // Helper to extract client number from clientName (e.g., "client42" -> 42)
    private int parseClientNum(String clientName) {
        String digits = clientName.replaceAll("\\D+", "");
        if (digits.isEmpty()) return 0;
        return Integer.parseInt(digits);
    }

    // Helper to extract a string field from a simple JSON object (no nested objects)
    private String extractJsonStringField(String json, String field) {
        String key = "\"" + field + "\":";
        int idx = json.indexOf(key);
        if (idx == -1) return null;
        int start = json.indexOf('"', idx + key.length());
        int end = json.indexOf('"', start + 1);
        if (start == -1 || end == -1) return null;
        return json.substring(start + 1, end);
    }

    

}
