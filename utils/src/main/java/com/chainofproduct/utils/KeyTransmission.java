package com.chainofproduct.utils;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

public class KeyTransmission {

	private java.net.ServerSocket listenerSocket;
	private java.util.concurrent.atomic.AtomicBoolean listenerRunning;

	// Default constructor
	public KeyTransmission() {
		listenerRunning = new java.util.concurrent.atomic.AtomicBoolean(false);
		listenerSocket = null;
	}

	public static boolean VERBOSE = true;
			/**
			 * Ensures EC keypair exists for the given storePrefix, then starts the key exchange listener.
			 * @param storePrefix Prefix for truststore and EC keystore file names
			 * @param listenPort Port to listen on
			 */
		public void ensureECKeyAndStartListener(String storePrefix, int listenPort) throws Exception {
			String ecKeystorePath = storePrefix + "-ec-keystore.p12";
			String ecAlias = storePrefix + "-ec";
			String ecPassword = "changeit";
			KeyPair ecKeyPair;
			java.io.File ecKeystoreFile = new java.io.File(ecKeystorePath);
			if (ecKeystoreFile.exists()) {
				try {
					java.security.PrivateKey priv = getMyECPrivateKey(ecKeystorePath, ecAlias);
					java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
					try (java.io.FileInputStream fis = new java.io.FileInputStream(ecKeystorePath)) {
						ks.load(fis, ecPassword.toCharArray());
					}
					java.security.PublicKey pub = ks.getCertificate(ecAlias).getPublicKey();
					ecKeyPair = new KeyPair(pub, priv);
				} catch (Exception e) {
					System.err.println("Error loading EC keypair, regenerating: " + e.getMessage());
					ecKeyPair = generateECKeyPairAndStore(ecAlias, ecKeystorePath, ecPassword);
				}
			} else {
				ecKeyPair = generateECKeyPairAndStore(ecAlias, ecKeystorePath, ecPassword);
			}
			this.startKeyExchangeListener(storePrefix, listenPort, ecKeyPair);
		}
		/**
		 * Starts a listening channel for key exchange requests on the specified port.
		 * Calls receiveRSAKeyAndCertWithECDH for each incoming connection.
		 * Use closeKeyExchangeListener() to stop the listener gracefully.
		 * @param storePrefix Prefix for truststore file names (e.g., "client" or "server")
		 * @param listenPort Port to listen on
		 * @param myECKeyPair Your EC keypair for ECDH
		 */
		public  void startKeyExchangeListener(String storePrefix, int listenPort, KeyPair myECKeyPair) throws Exception {
			listenerRunning.set(true);
			listenerSocket = new java.net.ServerSocket(listenPort);
			if (VERBOSE) System.out.println("[KeyExchange] Listener started on port " + listenPort);
			try {
				while (listenerRunning.get()) {
					try {
						listenerSocket.setSoTimeout(1000); // 1 second timeout for soft shutdown check
						Socket socket = null;
						try {
							socket = listenerSocket.accept();
						} catch (java.io.InterruptedIOException e) {
							// Timeout, check shutdown flag
							continue;
						} catch (java.net.SocketException se) {
							// Socket closed during shutdown
							if (!listenerRunning.get()) break;
							throw se;
						}
						if (!listenerRunning.get()) {
							if (socket != null && !socket.isClosed()) socket.close();
							break;
						}
						if (socket != null) {
							receiveRSAKeyAndCertWithECDH(storePrefix, socket, myECKeyPair);
							socket.close();
						}
					} catch (Exception e) {
						if (VERBOSE) {
							System.err.println("[KeyExchange] Error: " + e.getMessage());
						}
					}
				}
			} finally {
				if (listenerSocket != null && !listenerSocket.isClosed()) {
					try {
						listenerSocket.close();
					} catch (Exception e) {
						System.err.println("Error closing listener socket: " + e.getMessage());
					}
				}
				if (VERBOSE) System.out.println("[KeyExchange] Listener stopped.");
			}
		}

		/**
		 * Softly shuts down the key exchange listener.
		 */
		public void closeKeyExchangeListener() {
			listenerRunning.set(false);
			if (listenerSocket != null && !listenerSocket.isClosed()) {
				try {
					listenerSocket.close();
				} catch (Exception e) {
					System.err.println("Error closing listener socket: " + e.getMessage());
				}
			}
		}
	/**
	 * Receives an RSA key and certificate over a socket using ECDH key agreement and stores them in truststores.
	 * @param storePrefix Prefix for truststore file names (e.g., "client" or "server")
	 * @param peerAlias Alias for the peer (used for truststore entry)
	 * @param socket The connected socket to read from
	 * @param myECKeyPair Your EC keypair for ECDH
	 */
	public static void receiveRSAKeyAndCertWithECDH(String storePrefix, Socket socket, KeyPair myECKeyPair) throws Exception {
		InputStream in = socket.getInputStream();
		OutputStream out = socket.getOutputStream();

		byte[] aliasBytes = readBytes(in);
		String senderAlias = new String(aliasBytes, java.nio.charset.StandardCharsets.UTF_8);

		byte[] peerECPubBytes = readBytes(in);
		KeyFactory kf = KeyFactory.getInstance("EC");
		PublicKey peerECPublicKey = kf.generatePublic(new X509EncodedKeySpec(peerECPubBytes));

		byte[] myECPubBytes = myECKeyPair.getPublic().getEncoded();
		out.write(intToBytes(myECPubBytes.length));
		out.write(myECPubBytes);

		javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ECDH");
		ka.init(myECKeyPair.getPrivate());
		ka.doPhase(peerECPublicKey, true);
		byte[] sharedSecret = ka.generateSecret();

		byte[] peerEncryptedRSAKey = readBytes(in);
		byte[] peerEncryptedCert = readBytes(in);
		byte[] peerRSAKeyBytes = aesDecrypt(peerEncryptedRSAKey, sharedSecret);
		byte[] peerCertBytes = aesDecrypt(peerEncryptedCert, sharedSecret);

		PublicKey peerRSAPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(peerRSAKeyBytes));
		java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
		java.io.ByteArrayInputStream certStream = new java.io.ByteArrayInputStream(peerCertBytes);
		java.security.cert.Certificate peerCert = cf.generateCertificate(certStream);

		String truststoreFile = storePrefix + "-truststore.p12";
		String truststorePassword = "changeit";
		// Store the received peer certificate in our truststore
		Cerificates.storeTruststore(truststoreFile, truststorePassword, new String[]{senderAlias}, new java.security.cert.X509Certificate[]{(java.security.cert.X509Certificate)peerCert});

		String pubkeyTruststoreFile = storePrefix + "-truststore-pubkeys.p12";
		// Store the received peer public key in our pubkey truststore
		Cerificates.storePubKeyTruststore(pubkeyTruststoreFile, truststorePassword, new String[]{senderAlias}, new PublicKey[]{peerRSAPublicKey});
        // --- Mutual key/cert exchange: send our own RSA public key and certificate back to the sender ---

		// Load our own RSA public key and certificate from keystore using Cerificates logic
		String myEntityName = storePrefix;
		String myKeystorePath = myEntityName + "-keystore.p12";
		String myKeystorePassword = "changeit";
		java.security.KeyStore myKeystore = Cerificates.getKeystore(myEntityName, myKeystorePassword);
		if (myKeystore == null) {
			throw new java.io.FileNotFoundException("Keystore not found: " + myKeystorePath);
		}
		java.security.cert.Certificate myCert = myKeystore.getCertificate(myEntityName);
		if (myCert == null) {
			throw new java.security.cert.CertificateException("No certificate found for alias: " + myEntityName);
		}
		java.security.PublicKey myRSAPubKey = myCert.getPublicKey();

        // Encrypt our RSA public key and certificate with the shared secret
        byte[] myRSAPubKeyBytes = myRSAPubKey.getEncoded();
		byte[] myRSACertBytes = myCert.getEncoded();
        byte[] encryptedMyRSAPubKey = aesEncrypt(myRSAPubKeyBytes, sharedSecret);
        byte[] encryptedMyRSACert = aesEncrypt(myRSACertBytes, sharedSecret);

		out.write(intToBytes(encryptedMyRSAPubKey.length));
		out.write(encryptedMyRSAPubKey);
		out.write(intToBytes(encryptedMyRSACert.length));
		out.write(encryptedMyRSACert);
		out.flush();
	}

	/**
	 * Establishes a TCP connection to the receiver, performs ECDH key agreement to derive a shared secret,
	 * then uses the shared secret to encrypt and send the RSA key and certificate.
	 * @param receiverIp Receiver's IP address
	 * @param receiverPort Receiver's port
	 * @param myECKeyPair Your EC keypair for ECDH
	 * @param myRSAPublicKey Your RSA public key to send
	 * @param myCertificate Your X509 certificate to send
	 */
	/**
	 * @param storePrefix Prefix for truststore file names (e.g., "client" or "server")
	 */
	/**
	 * @param storePrefix Prefix for truststore file names (e.g., "client" or "server")
	 * @param peerAlias Alias for the peer (used for truststore entry)
	 */
	public static void sendRSAKeyAndCertWithECDH(String storePrefix,String myAlias ,String peerAlias, String receiverIp, int receiverPort, KeyPair myECKeyPair, PublicKey myRSAPublicKey, X509Certificate myCertificate) throws Exception {
					// --- VERBOSE: log all received messages/data ---
		try (Socket socket = new Socket(receiverIp, receiverPort)) {
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();


			byte[] myAliasBytes = myAlias.getBytes(java.nio.charset.StandardCharsets.UTF_8);
			out.write(intToBytes(myAliasBytes.length));
			out.write(myAliasBytes);


			byte[] myECPubBytes = myECKeyPair.getPublic().getEncoded();
			out.write(intToBytes(myECPubBytes.length));
			out.write(myECPubBytes);


			byte[] peerECPubBytes = readBytes(in);

			KeyFactory kf = KeyFactory.getInstance("EC");
			PublicKey peerECPublicKey = kf.generatePublic(new X509EncodedKeySpec(peerECPubBytes));


			javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ECDH");
			ka.init(myECKeyPair.getPrivate());
			ka.doPhase(peerECPublicKey, true);
			byte[] sharedSecret = ka.generateSecret();


			byte[] rsaKeyBytes = myRSAPublicKey.getEncoded();
			byte[] certBytes = myCertificate.getEncoded();


			byte[] encryptedRSAKey = aesEncrypt(rsaKeyBytes, sharedSecret);
			byte[] encryptedCert = aesEncrypt(certBytes, sharedSecret);


			out.write(intToBytes(encryptedRSAKey.length));
			out.write(encryptedRSAKey);

			out.write(intToBytes(encryptedCert.length));
			out.write(encryptedCert);
			// After sending, log all received data

			byte[] peerEncryptedRSAKey = readBytes(in);

			byte[] peerEncryptedCert = readBytes(in);

			byte[] peerRSAKeyBytes = aesDecrypt(peerEncryptedRSAKey, sharedSecret);
			byte[] peerCertBytes = aesDecrypt(peerEncryptedCert, sharedSecret);

			PublicKey peerRSAPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(peerRSAKeyBytes));
			java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
			java.io.ByteArrayInputStream certStream = new java.io.ByteArrayInputStream(peerCertBytes);
			java.security.cert.Certificate peerCert = cf.generateCertificate(certStream);


			String truststorePassword = "changeit";
			// Use the getter to load the truststore (or create new if null)
			java.security.KeyStore truststore = Cerificates.getTruststore(storePrefix, truststorePassword);
			if (truststore == null) {
				// If truststore doesn't exist, create and store
				Cerificates.storeTruststore(storePrefix + "-truststore.p12", truststorePassword, new String[]{peerAlias}, new java.security.cert.X509Certificate[]{(java.security.cert.X509Certificate)peerCert});
			} else {
				truststore.setCertificateEntry(peerAlias, (java.security.cert.X509Certificate)peerCert);
				try (java.io.FileOutputStream fos = new java.io.FileOutputStream(storePrefix + "-truststore.p12")) {
					truststore.store(fos, truststorePassword.toCharArray());
				}
			}


			java.security.KeyStore pubkeyTruststore = Cerificates.getPubKeyTruststore(storePrefix, truststorePassword);
			if (pubkeyTruststore == null) {
				Cerificates.storePubKeyTruststore(storePrefix + "-truststore-pubkeys.p12", truststorePassword, new String[]{peerAlias}, new PublicKey[]{peerRSAPublicKey});
			} else {
				// Generate a self-signed cert for the public key as in Cerificates.storePubKeyTruststore
				java.security.cert.Certificate pubkeyCert = Cerificates.generateSelfSignedCertificate(new KeyPair(peerRSAPublicKey, Cerificates.generateDeterministicKeyPair("pubkey-temp").getPrivate()), "CN=" + peerAlias + "-pubkey, OU=Org, O=Company, L=City, ST=State, C=PT");
				pubkeyTruststore.setCertificateEntry(peerAlias + "-pubkey", pubkeyCert);
				try (java.io.FileOutputStream fos = new java.io.FileOutputStream(storePrefix + "-truststore-pubkeys.p12")) {
					pubkeyTruststore.store(fos, truststorePassword.toCharArray());
				}
			}
		}
	}

	// AES decryption using shared secret (first 16 bytes as key)
	private static byte[] aesDecrypt(byte[] data, byte[] sharedSecret) throws Exception {
		javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(sharedSecret, 0, 16, "AES");
		javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec);
		return cipher.doFinal(data);
	}

	// AES encryption using shared secret (first 16 bytes as key)
	private static byte[] aesEncrypt(byte[] data, byte[] sharedSecret) throws Exception {
		javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(sharedSecret, 0, 16, "AES");
		javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec);
		return cipher.doFinal(data);
	}

	// Helper to read a length-prefixed byte array
	static byte[] readBytes(InputStream in) throws Exception {
		byte[] lenBytes = in.readNBytes(4);
		int len = bytesToInt(lenBytes);
		return in.readNBytes(len);
	}

	static byte[] intToBytes(int value) {
		return new byte[] {
			(byte)(value >>> 24),
			(byte)(value >>> 16),
			(byte)(value >>> 8),
			(byte)value
		};
	}

	static int bytesToInt(byte[] bytes) {
		return ((bytes[0] & 0xFF) << 24) |
			   ((bytes[1] & 0xFF) << 16) |
			   ((bytes[2] & 0xFF) << 8) |
			   (bytes[3] & 0xFF);
	}


	/**
	 * Loads the EC private key from a PKCS12 keystore with password 'changeit'.
	 * @param keystorePath Path to the PKCS12 keystore
	 * @param alias Alias of the key entry
	 * @return The EC PrivateKey
	 */
	public static java.security.PrivateKey getMyECPrivateKey(String keystorePath, String alias) throws Exception {
		String password = "changeit";
		java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
		try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
			ks.load(fis, password.toCharArray());
		}
		java.security.Key key = ks.getKey(alias, password.toCharArray());
		if (key instanceof java.security.PrivateKey) {
			return (java.security.PrivateKey) key;
		} else {
			throw new java.security.UnrecoverableKeyException("No EC private key found for alias: " + alias);
		}
	}

    
	/**
	 * Generates an EC key pair using the secp256r1 curve (NIST P-256).
	 * @return KeyPair (EC)
	 */
	public static KeyPair generateECKeyPairAndStore(String alias, String keystorePath, String password) throws Exception {
		java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("EC");
		java.security.spec.ECGenParameterSpec ecSpec = new java.security.spec.ECGenParameterSpec("secp256r1");
		keyGen.initialize(ecSpec);
		KeyPair keyPair = keyGen.generateKeyPair();

		// Store only the private key (no certificate)
		java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
		java.io.File keystoreFile = new java.io.File(keystorePath);
		if (keystoreFile.exists()) {
			try (java.io.FileInputStream fis = new java.io.FileInputStream(keystoreFile)) {
				ks.load(fis, password.toCharArray());
			}
		} else {
			ks.load(null, null);
		}
		// Use a dummy certificate (required by PKCS12, but not a real cert)
		java.security.cert.Certificate[] dummyChain = { generateDummySelfSignedCert(keyPair) };
		ks.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), dummyChain);
		try (java.io.FileOutputStream fos = new java.io.FileOutputStream(keystorePath)) {
			ks.store(fos, password.toCharArray());
		}
		return keyPair;
	}

	// Generate a minimal dummy self-signed certificate for PKCS12 storage (not for authentication)
	private static java.security.cert.Certificate generateDummySelfSignedCert(KeyPair keyPair) throws Exception {
		// Use Bouncy Castle for a minimal cert
		org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name("CN=dummy");
		long now = System.currentTimeMillis();
		java.util.Date from = new java.util.Date(now);
		java.util.Date to = new java.util.Date(now + 24L * 60 * 60 * 1000); // 1 day
		java.math.BigInteger sn = new java.math.BigInteger(64, new java.security.SecureRandom());
		org.bouncycastle.cert.X509v3CertificateBuilder certBuilder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
			subject, sn, from, to, subject, keyPair.getPublic());
		org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
			.setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()).build(keyPair.getPrivate());
		org.bouncycastle.cert.X509CertificateHolder certHolder = certBuilder.build(signer);
		return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
			.setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
			.getCertificate(certHolder);
	}

}
