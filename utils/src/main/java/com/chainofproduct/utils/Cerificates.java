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

	public static void main(String[] args) {
		if (args.length < 1) {
			System.err.println("Usage: java Cerificates <server|db|client N>");
			System.exit(1);
		}
		try {
			switch (args[0].toLowerCase()) {
				case "server":
					generateForServer();
					break;
				case "db":
					generateForDb();
					break;
				case "client":
					if (args.length < 2) {
						System.err.println("Usage: java Cerificates client <clientNum>");
						System.exit(1);
					}
					int clientNum = Integer.parseInt(args[1]);
					if (clientNum < 0 || clientNum > 999) {
						System.err.println("Client number must be between 0 and 999");
						System.exit(1);
					}
					generateForClient(clientNum);
					break;
				default:
					System.err.println("Unknown mode: " + args[0]);
					System.exit(1);
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}


	// Server: generate all keypairs, store all public certs, store only server private key
	private static void generateForServer() throws Exception {
		int numClients = 1000;
		String[] allEntities = new String[numClients + 2];
		allEntities[0] = "server";
		allEntities[1] = "db";
		for (int i = 0; i < numClients; i++) allEntities[i + 2] = "client" + i;

		KeyPair[] keyPairs = new KeyPair[allEntities.length];
		X509Certificate[] certs = new X509Certificate[allEntities.length];
		for (int i = 0; i < allEntities.length; i++) {
			String name = allEntities[i];
			String dn = "CN=" + name + ", OU=Org, O=Company, L=City, ST=State, C=PT";
			keyPairs[i] = generateDeterministicKeyPair(name);
			certs[i] = generateSelfSignedCertificate(keyPairs[i], dn);
		}
		// Store only server private key/cert
		String alias = "server";
		String keystoreFile = alias + "-keystore.p12";
		String keystorePassword = "changeit";
		storeKeyAndCert(keystoreFile, keystorePassword, alias, keyPairs[0], certs[0]);
		// Store all public certs
		String truststoreFile = alias + "-truststore.p12";
		storeTruststore(truststoreFile, keystorePassword, allEntities, certs, 0);
		// Store all public keys in a separate truststore
		String pubkeyTruststoreFile = alias + "-truststore-pubkeys.p12";
		PublicKey[] pubKeys = new PublicKey[allEntities.length];
		for (int i = 0; i < allEntities.length; i++) pubKeys[i] = keyPairs[i].getPublic();
		Cerificates.storePubKeyTruststore(pubkeyTruststoreFile, keystorePassword, allEntities, pubKeys);
		System.out.println("Generated for server:");
		System.out.println("  Private keystore: " + keystoreFile);
		System.out.println("  Truststore (all public certs): " + truststoreFile);
	}

	// Client: generate server keypair/cert, store only server public cert, generate own keypair/cert and store pair
	private static void generateForClient(int clientNum) throws Exception {
		int numClients = 1000;
		String[] allEntities = new String[numClients + 2];
		allEntities[0] = "server";
		allEntities[1] = "db";
		for (int i = 0; i < numClients; i++) allEntities[i + 2] = "client" + i;

		// Generate server and this client
		KeyPair serverKeyPair = generateDeterministicKeyPair("server");
		X509Certificate serverCert = generateSelfSignedCertificate(serverKeyPair, "CN=server, OU=Org, O=Company, L=City, ST=State, C=PT");
		String serverTruststore = "client" + clientNum + "-truststore.p12";
		storeTruststore(serverTruststore, "changeit", new String[]{"server"}, new X509Certificate[]{serverCert}, 0);
		// Store server public key in a separate truststore
		String pubkeyTruststore = "client" + clientNum + "-truststore-pubkeys.p12";
		Cerificates.storePubKeyTruststore(pubkeyTruststore, "changeit", new String[]{"server"}, new PublicKey[]{serverKeyPair.getPublic()});

		KeyPair clientKeyPair = generateDeterministicKeyPair("client" + clientNum);
		X509Certificate clientCert = generateSelfSignedCertificate(clientKeyPair, "CN=client" + clientNum + ", OU=Org, O=Company, L=City, ST=State, C=PT");
		String clientKeystore = "client" + clientNum + "-keystore.p12";
		storeKeyAndCert(clientKeystore, "changeit", "client" + clientNum, clientKeyPair, clientCert);

		System.out.println("Generated for client" + clientNum + ":");
		System.out.println("  Private keystore: " + clientKeystore);
		System.out.println("  Truststore (server public cert): " + serverTruststore);
	}

	// DB: generate server keypair/cert, store only server public cert, generate own keypair/cert and store pair
	private static void generateForDb() throws Exception {
		KeyPair serverKeyPair = generateDeterministicKeyPair("server");
		X509Certificate serverCert = generateSelfSignedCertificate(serverKeyPair, "CN=server, OU=Org, O=Company, L=City, ST=State, C=PT");
		String serverTruststore = "db-truststore.p12";
		storeTruststore(serverTruststore, "changeit", new String[]{"server"}, new X509Certificate[]{serverCert}, 0);
		// Store server public key in a separate truststore
		String pubkeyTruststore = "db-truststore-pubkeys.p12";
		Cerificates.storePubKeyTruststore(pubkeyTruststore, "changeit", new String[]{"server"}, new PublicKey[]{serverKeyPair.getPublic()});

		KeyPair dbKeyPair = generateDeterministicKeyPair("db");
		X509Certificate dbCert = generateSelfSignedCertificate(dbKeyPair, "CN=db, OU=Org, O=Company, L=City, ST=State, C=PT");
		String dbKeystore = "db-keystore.p12";
		storeKeyAndCert(dbKeystore, "changeit", "db", dbKeyPair, dbCert);

		System.out.println("Generated for db:");
		System.out.println("  Private keystore: " + dbKeystore);
		System.out.println("  Truststore (server public cert): " + serverTruststore);
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

	// Deterministic RSA keypair from entity name
	private static KeyPair generateDeterministicKeyPair(String name) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		byte[] seed = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(seed);
		keyGen.initialize(2048, sr);
		return keyGen.generateKeyPair();
	}

	// Self-signed X.509 certificate
	private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String dn) throws Exception {
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
	private static void storeTruststore(String truststorePath, String password, String[] allEntities, X509Certificate[] certs, int selfIdx) throws Exception {
		KeyStore ts = KeyStore.getInstance("PKCS12");
		ts.load(null, null);
		for (int i = 0; i < allEntities.length; i++) {
			ts.setCertificateEntry(allEntities[i], certs[i]);
		}
		try (FileOutputStream fos = new FileOutputStream(truststorePath)) {
			ts.store(fos, password.toCharArray());
		}
	}


}
