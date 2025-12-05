package com.chainofproduct.utils;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Cerificates {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	/**
	 * Verifies if the receiver's certificate and public key are available in the truststores.
	 * If not, triggers certificate/key exchange.
	 * @param myEntityName The name of this entity (client/server)
	 * @param receiverName The name of the receiver entity (partner)
	 * @param receiverIp The IP address of the receiver
	 * @param receiverPort The port of the receiver
	 * @throws Exception if exchange fails
	 */
	public static void verifyCertificaAndObtain(String myEntityName, String receiverName, String receiverIp, int receiverPort) throws Exception {
		String password = "changeit";
		boolean certFound = false;
		boolean pubkeyFound = false;
		// Check for certificate using new getter
		KeyStore truststore = getTruststore(myEntityName, password);
		if (truststore != null) {
			java.security.cert.Certificate cert = truststore.getCertificate(receiverName);
			certFound = (cert != null);
		}
		// Check for public key using new getter
		KeyStore pubkeyTs = getPubKeyTruststore(myEntityName, password);
		if (pubkeyTs != null) {
			java.security.cert.Certificate pubkeyCert = pubkeyTs.getCertificate(receiverName + "-pubkey");
			pubkeyFound = (pubkeyCert != null);
		}
		if (!certFound || !pubkeyFound) {
			// Trigger certificate/key exchange
			System.out.println("Certificate or public key for " + receiverName + " not found. Initiating exchange...");
			// Load my EC keypair
			String ecKeystorePath = myEntityName + "-ec-keystore.p12";
			String ecAlias = myEntityName + "-ec";
			java.security.KeyPair myECKeyPair = com.chainofproduct.utils.KeyTransmission.generateECKeyPairAndStore(ecAlias, ecKeystorePath, password);
			// Load my RSA public key and certificate using new getter
			KeyStore ks = getKeystore(myEntityName, password);
			if (ks != null) {
				java.security.cert.Certificate myCert = ks.getCertificate(myEntityName);
				java.security.PublicKey myRSAPubKey = myCert.getPublicKey();
				com.chainofproduct.utils.KeyTransmission.sendRSAKeyAndCertWithECDH(
					myEntityName, myEntityName, receiverName, receiverIp, receiverPort, myECKeyPair, myRSAPubKey, (java.security.cert.X509Certificate)myCert
				);
			} else {
				throw new Exception("Keystore for " + myEntityName + " not found.");
			}
		} else {
			System.out.println("Certificate and public key for " + receiverName + " found in truststores.");
		}
	}

	public static void main(String[] args) {
		if (args.length < 1) {
			System.err.println("Usage: java Cerificates <entityName>");
			System.exit(1);
		}
		String entityName = args[0];
		try {
			generateForEntity(entityName);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}



	// Generate and store one keypair and certificate for the given entity
	private static void generateForEntity(String entityName) throws Exception {
		// Also generate and store EC key pair (no certificate, just for ECDH, etc.)
		String ecKeystoreFile = entityName + "-ec-keystore.p12";
		String ecKeystorePassword = "changeit";
		com.chainofproduct.utils.KeyTransmission.generateECKeyPairAndStore(entityName + "-ec", ecKeystoreFile, ecKeystorePassword);
		KeyPair keyPair = generateDeterministicKeyPair(entityName);
		String dn = "CN=" + entityName + ", OU=Org, O=Company, L=City, ST=State, C=PT";
		X509Certificate cert = generateSelfSignedCertificate(keyPair, dn);

		String keystoreFile = entityName + "-keystore.p12";
		String keystorePassword = "changeit";
		storeKeyAndCert(keystoreFile, keystorePassword, entityName, keyPair, cert);

		String truststoreFile = entityName + "-truststore.p12";
		storeTruststore(truststoreFile, keystorePassword, new String[]{entityName}, new X509Certificate[]{cert}, 0);

		String pubkeyTruststoreFile = entityName + "-truststore-pubkeys.p12";
		Cerificates.storePubKeyTruststore(pubkeyTruststoreFile, keystorePassword, new String[]{entityName}, new PublicKey[]{keyPair.getPublic()});

		System.out.println("Generated for " + entityName + ":");
		System.out.println("  Private keystore: " + keystoreFile);
		System.out.println("  Truststore (public cert): " + truststoreFile);
		System.out.println("  Truststore (public key): " + pubkeyTruststoreFile);
	}

	// Deterministic RSA keypair from entity name
	public static KeyPair generateDeterministicKeyPair(String name) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		byte[] seed = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(seed);
		keyGen.initialize(2048, sr);
		return keyGen.generateKeyPair();
	}

	// Self-signed X.509 certificate
	public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String dn) throws Exception {
		long now = 1672531200000L; // Fixed notBefore (2023-01-01 UTC)
		Date from = new Date(now);
		Date to = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year
		BigInteger sn = new BigInteger(64, new SecureRandom(dn.getBytes()));
		X500Name subject = new X500Name(dn);
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				subject, sn, from, to, subject, keyPair.getPublic());
		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
	}

	// Store private key and cert in PKCS12 keystore
	private static void storeKeyAndCert(String keystorePath, String password, String alias, KeyPair keyPair, X509Certificate cert) throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(null, null);
		ks.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[]{cert});
		try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
			ks.store(fos, password.toCharArray());
		}
	}

	// Store all public certs in a truststore (except own private key)
	public static void storeTruststore(String truststorePath, String password, String[] allEntities, X509Certificate[] certs, int selfIdx) throws Exception {
		KeyStore ts = KeyStore.getInstance("PKCS12");
		ts.load(null, null);
		for (int i = 0; i < allEntities.length; i++) {
			ts.setCertificateEntry(allEntities[i], certs[i]);
		}
		try (FileOutputStream fos = new FileOutputStream(truststorePath)) {
			ts.store(fos, password.toCharArray());
		}
	}

	// Store all public keys in a PKCS12 truststore (as encoded bytes)
	public static void storePubKeyTruststore(String truststorePath, String password, String[] allEntities, PublicKey[] pubKeys) throws Exception {
		KeyStore ts = KeyStore.getInstance("PKCS12");
		ts.load(null, null);
		for (int i = 0; i < allEntities.length; i++) {
			java.security.cert.Certificate cert = generateSelfSignedCertificate(new KeyPair(pubKeys[i], generateDeterministicKeyPair("pubkey-temp").getPrivate()), "CN=" + allEntities[i] + "-pubkey, OU=Org, O=Company, L=City, ST=State, C=PT");
			ts.setCertificateEntry(allEntities[i] + "-pubkey", cert);
		}
		try (FileOutputStream fos = new FileOutputStream(truststorePath)) {
			ts.store(fos, password.toCharArray());
		}
	}

	
	/**
	 * Loads and returns the truststore for the given entity.
	 */
	public static KeyStore getTruststore(String entityName, String password) throws Exception {
		String truststorePath = entityName + "-truststore.p12";
		KeyStore ts = KeyStore.getInstance("PKCS12");
		java.io.File truststoreFile = new java.io.File(truststorePath);
		if (!truststoreFile.exists()) return null;
		try (java.io.FileInputStream fis = new java.io.FileInputStream(truststoreFile)) {
			ts.load(fis, password.toCharArray());
		}
		return ts;
	}

	/**
	 * Loads and returns the pubkey truststore for the given entity.
	 */
	public static KeyStore getPubKeyTruststore(String entityName, String password) throws Exception {
		String pubkeyTruststorePath = entityName + "-truststore-pubkeys.p12";
		KeyStore ts = KeyStore.getInstance("PKCS12");
		java.io.File pubkeyTruststoreFile = new java.io.File(pubkeyTruststorePath);
		if (!pubkeyTruststoreFile.exists()) return null;
		try (java.io.FileInputStream fis = new java.io.FileInputStream(pubkeyTruststoreFile)) {
			ts.load(fis, password.toCharArray());
		}
		return ts;
	}

	/**
	 * Loads and returns the keystore for the given entity.
	 */
	public static KeyStore getKeystore(String entityName, String password) throws Exception {
		String keystorePath = entityName + "-keystore.p12";
		KeyStore ks = KeyStore.getInstance("PKCS12");
		java.io.File keystoreFile = new java.io.File(keystorePath);
		if (!keystoreFile.exists()) return null;
		try (java.io.FileInputStream fis = new java.io.FileInputStream(keystoreFile)) {
			ks.load(fis, password.toCharArray());
		}
		return ks;
	}



}
