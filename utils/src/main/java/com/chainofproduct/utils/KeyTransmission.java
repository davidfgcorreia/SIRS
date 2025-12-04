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
	 * Establishes a TCP connection to the receiver, performs ECDH key agreement to derive a shared secret,
	 * then uses the shared secret to encrypt and send the RSA key and certificate.
	 * @param receiverIp Receiver's IP address
	 * @param receiverPort Receiver's port
	 * @param myECKeyPair Your EC keypair for ECDH
	 * @param myRSAPublicKey Your RSA public key to send
	 * @param myCertificate Your X509 certificate to send
	 */
	public static void sendRSAKeyAndCertWithECDH(String receiverIp, int receiverPort, KeyPair myECKeyPair, PublicKey myRSAPublicKey, X509Certificate myCertificate) throws Exception {
		try (Socket socket = new Socket(receiverIp, receiverPort)) {
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();

			// 1. ECDH key exchange
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
		}
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
