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
			/**
			 * Ensures EC keypair exists for the given storePrefix, then starts the key exchange listener.
			 * @param storePrefix Prefix for truststore and EC keystore file names
			 * @param listenPort Port to listen on
			 */
			public static void ensureECKeyAndStartListener(String storePrefix, int listenPort) throws Exception {
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
				startKeyExchangeListener(storePrefix, listenPort, ecKeyPair);
			}
		// Soft shutdown flag for the key exchange listener
		private static final java.util.concurrent.atomic.AtomicBoolean listenerRunning = new java.util.concurrent.atomic.AtomicBoolean(false);
		private static java.net.ServerSocket listenerSocket = null;

		/**
		 * Starts a listening channel for key exchange requests on the specified port.
		 * Calls receiveRSAKeyAndCertWithECDH for each incoming connection.
		 * Use closeKeyExchangeListener() to stop the listener gracefully.
		 * @param storePrefix Prefix for truststore file names (e.g., "client" or "server")
		 * @param listenPort Port to listen on
		 * @param myECKeyPair Your EC keypair for ECDH
		 */
		public static void startKeyExchangeListener(String storePrefix, int listenPort, KeyPair myECKeyPair) throws Exception {
			listenerRunning.set(true);
			listenerSocket = new java.net.ServerSocket(listenPort);
			System.out.println("Key exchange listener started on port " + listenPort);
			while (listenerRunning.get()) {
				try {
					listenerSocket.setSoTimeout(1000); // 1 second timeout for soft shutdown check
					Socket socket = null;
					try {
						socket = listenerSocket.accept();
					} catch (java.io.InterruptedIOException e) {
						// Timeout, check shutdown flag
						continue;
					}
					if (socket != null) {
						System.out.println("Received key exchange request from " + socket.getInetAddress());
						receiveRSAKeyAndCertWithECDH(storePrefix, socket, myECKeyPair);
						System.out.println("Key exchange completed for " + socket.getInetAddress());
						socket.close();
					}
				} catch (Exception e) {
					System.err.println("Error during key exchange: " + e.getMessage());
					e.printStackTrace();
				}
			}
			if (listenerSocket != null && !listenerSocket.isClosed()) {
				listenerSocket.close();
			}
			System.out.println("Key exchange listener stopped.");
		}

		/**
		 * Softly shuts down the key exchange listener.
		 */
		public static void closeKeyExchangeListener() {
			listenerRunning.set(false);
			try {
				if (listenerSocket != null && !listenerSocket.isClosed()) {
					listenerSocket.close();
				}
			} catch (Exception e) {
				System.err.println("Error closing key exchange listener: " + e.getMessage());
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

		// 1. Receive sender's alias
		byte[] aliasBytes = readBytes(in);
		String senderAlias = new String(aliasBytes, java.nio.charset.StandardCharsets.UTF_8);

		// 2. Receive peer EC public key
		byte[] peerECPubBytes = readBytes(in);
		KeyFactory kf = KeyFactory.getInstance("EC");
		PublicKey peerECPublicKey = kf.generatePublic(new X509EncodedKeySpec(peerECPubBytes));

		// 3. Send our EC public key
		byte[] myECPubBytes = myECKeyPair.getPublic().getEncoded();
		out.write(intToBytes(myECPubBytes.length));
		out.write(myECPubBytes);

		// 3. Derive shared secret
		javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ECDH");
		ka.init(myECKeyPair.getPrivate());
		ka.doPhase(peerECPublicKey, true);
		byte[] sharedSecret = ka.generateSecret();

		// 4. Receive encrypted RSA key and certificate
		byte[] peerEncryptedRSAKey = readBytes(in);
		byte[] peerEncryptedCert = readBytes(in);
		byte[] peerRSAKeyBytes = aesDecrypt(peerEncryptedRSAKey, sharedSecret);
		byte[] peerCertBytes = aesDecrypt(peerEncryptedCert, sharedSecret);

		// 5. Reconstruct public key and certificate
		PublicKey peerRSAPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(peerRSAKeyBytes));
		java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
		java.io.ByteArrayInputStream certStream = new java.io.ByteArrayInputStream(peerCertBytes);
		java.security.cert.Certificate peerCert = cf.generateCertificate(certStream);

		// 6. Store all peer certificates in the same <senderAlias>-truststore.p12 file
		String truststoreFile = senderAlias + "-truststore.p12";
		String truststorePassword = "changeit";
		java.security.KeyStore truststore = java.security.KeyStore.getInstance("PKCS12");
		java.io.File truststoreF = new java.io.File(truststoreFile);
		if (truststoreF.exists()) {
			try (java.io.FileInputStream fis = new java.io.FileInputStream(truststoreF)) {
				truststore.load(fis, truststorePassword.toCharArray());
			}
		} else {
			truststore.load(null, null);
		}
		String uniquePeerCertAlias = senderAlias + "-" + System.currentTimeMillis();
		truststore.setCertificateEntry(uniquePeerCertAlias, peerCert);
		try (java.io.FileOutputStream fos = new java.io.FileOutputStream(truststoreFile)) {
			truststore.store(fos, truststorePassword.toCharArray());
		}

		// 7. Store all peer public keys in the same <senderAlias>-truststore-pubkeys.p12 file
		String pubkeyTruststoreFile = senderAlias + "-truststore-pubkeys.p12";
		String pubkeyTruststorePassword = "changeit";
		java.security.KeyStore pubkeyTs = java.security.KeyStore.getInstance("PKCS12");
		java.io.File pubkeyTsFile = new java.io.File(pubkeyTruststoreFile);
		if (pubkeyTsFile.exists()) {
			try (java.io.FileInputStream fis = new java.io.FileInputStream(pubkeyTsFile)) {
				pubkeyTs.load(fis, pubkeyTruststorePassword.toCharArray());
			}
		} else {
			pubkeyTs.load(null, null);
		}
		String uniquePeerPubkeyAlias = senderAlias + "-pubkey";
		java.security.cert.Certificate[] dummyChain = { generateDummySelfSignedCert(new KeyPair(peerRSAPublicKey, myECKeyPair.getPrivate())) };
		pubkeyTs.setCertificateEntry(uniquePeerPubkeyAlias, dummyChain[0]);
		try (java.io.FileOutputStream fos = new java.io.FileOutputStream(pubkeyTruststoreFile)) {
			pubkeyTs.store(fos, pubkeyTruststorePassword.toCharArray());
		}
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
		try (Socket socket = new Socket(receiverIp, receiverPort)) {
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();

			// 1. Send our alias first
			byte[] myAliasBytes = myAlias.getBytes(java.nio.charset.StandardCharsets.UTF_8);
			out.write(intToBytes(myAliasBytes.length));
			out.write(myAliasBytes);

			// 2. ECDH key exchange
			byte[] myECPubBytes = myECKeyPair.getPublic().getEncoded();
			out.write(intToBytes(myECPubBytes.length));
			out.write(myECPubBytes);

			byte[] peerECPubBytes = readBytes(in);
			KeyFactory kf = KeyFactory.getInstance("EC");
			PublicKey peerECPublicKey = kf.generatePublic(new X509EncodedKeySpec(peerECPubBytes));

			// Derive shared secret
			javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ECDH");
			ka.init(myECKeyPair.getPrivate());
			ka.doPhase(peerECPublicKey, true);
			byte[] sharedSecret = ka.generateSecret();

			// 2. Encrypt RSA key and certificate with shared secret
			byte[] rsaKeyBytes = myRSAPublicKey.getEncoded();
			byte[] certBytes = myCertificate.getEncoded();
			byte[] encryptedRSAKey = aesEncrypt(rsaKeyBytes, sharedSecret);
			byte[] encryptedCert = aesEncrypt(certBytes, sharedSecret);

			// 3. Send encrypted RSA key and certificate
			out.write(intToBytes(encryptedRSAKey.length));
			out.write(encryptedRSAKey);
			out.write(intToBytes(encryptedCert.length));
			out.write(encryptedCert);

			// 4. Receive peer's encrypted RSA key and certificate
			byte[] peerEncryptedRSAKey = readBytes(in);
			byte[] peerEncryptedCert = readBytes(in);
			byte[] peerRSAKeyBytes = aesDecrypt(peerEncryptedRSAKey, sharedSecret);
			byte[] peerCertBytes = aesDecrypt(peerEncryptedCert, sharedSecret);

			// Reconstruct public key and certificate
			PublicKey peerRSAPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(peerRSAKeyBytes));
			java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
			java.io.ByteArrayInputStream certStream = new java.io.ByteArrayInputStream(peerCertBytes);
			java.security.cert.Certificate peerCert = cf.generateCertificate(certStream);

			// Store all peer certificates in the same <storePrefix>-truststore.p12 file
			String truststoreFile = storePrefix + "-truststore.p12";
			String truststorePassword = "changeit";
			java.security.KeyStore truststore = java.security.KeyStore.getInstance("PKCS12");
			java.io.File truststoreF = new java.io.File(truststoreFile);
			if (truststoreF.exists()) {
				try (java.io.FileInputStream fis = new java.io.FileInputStream(truststoreF)) {
					truststore.load(fis, truststorePassword.toCharArray());
				}
			} else {
				truststore.load(null, null);
			}
			// Use a unique alias for each peer certificate
			String uniquePeerCertAlias = peerAlias + "-" + System.currentTimeMillis();
			truststore.setCertificateEntry(uniquePeerCertAlias, peerCert);
			try (java.io.FileOutputStream fos = new java.io.FileOutputStream(truststoreFile)) {
				truststore.store(fos, truststorePassword.toCharArray());
			}

			// Store all peer public keys in the same <storePrefix>-truststore-pubkeys.p12 file
			String pubkeyTruststoreFile = storePrefix + "-truststore-pubkeys.p12";
			String pubkeyTruststorePassword = "changeit";
			java.security.KeyStore pubkeyTs = java.security.KeyStore.getInstance("PKCS12");
			java.io.File pubkeyTsFile = new java.io.File(pubkeyTruststoreFile);
			if (pubkeyTsFile.exists()) {
				try (java.io.FileInputStream fis = new java.io.FileInputStream(pubkeyTsFile)) {
					pubkeyTs.load(fis, pubkeyTruststorePassword.toCharArray());
				}
			} else {
				pubkeyTs.load(null, null);
			}
			// Use a unique alias for each peer public key
			String uniquePeerPubkeyAlias = peerAlias + "-pubkey";
			java.security.cert.Certificate[] dummyChain = { generateDummySelfSignedCert(new KeyPair(peerRSAPublicKey, myECKeyPair.getPrivate())) };
			pubkeyTs.setCertificateEntry(uniquePeerPubkeyAlias, dummyChain[0]);
			try (java.io.FileOutputStream fos = new java.io.FileOutputStream(pubkeyTruststoreFile)) {
				pubkeyTs.store(fos, pubkeyTruststorePassword.toCharArray());
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
	private static byte[] readBytes(InputStream in) throws Exception {
		byte[] lenBytes = in.readNBytes(4);
		int len = bytesToInt(lenBytes);
		return in.readNBytes(len);
	}

	private static byte[] intToBytes(int value) {
		return new byte[] {
			(byte)(value >>> 24),
			(byte)(value >>> 16),
			(byte)(value >>> 8),
			(byte)value
		};
	}

	private static int bytesToInt(byte[] bytes) {
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
