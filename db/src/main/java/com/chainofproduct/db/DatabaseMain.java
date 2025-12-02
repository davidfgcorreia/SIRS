package com.chainofproduct.db;

import java.io.IOException;
import java.net.*;
import com.chainofproduct.utils.ApiCalls;

public class DatabaseMain {

  public static void main(String[] args) {
    // Ensure database keys exist before starting
    ensureKeysExist("database");
    
    int port = 5432;

    try (ServerSocket DatabaseSocket = new ServerSocket(port)) {
      System.out.println("Server is listening on port " + port);

      while (true) {

        Socket socket = DatabaseSocket.accept();
        System.out.println("New request accepted");

        ServerExecutorImpl executor = new ServerExecutorImpl();

        new Thread(() -> {
          try {
            ApiCalls.handleClient(socket, executor);
          } catch (Exception e) {
            // do something
          }

        }).start();

      }

    } catch (IOException e) {
      // do something
    }

  }
  
  /**
   * Ensures RSA keypair exists for the database, generating if necessary.
   */
  private static void ensureKeysExist(String entityName) {
    java.io.File privateKeyFile = new java.io.File("keys/" + entityName + "-private.key");
    java.io.File publicKeyFile = new java.io.File("keys/" + entityName + "-public.key");
    
    if (privateKeyFile.exists() && publicKeyFile.exists()) {
      return;
    }
    
    System.out.println("Database keys not found. Generating new RSA-2048 keypair...");
    
    try {
      // Generate keypair using Java KeyPairGenerator
      java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(2048);
      java.security.KeyPair keyPair = keyGen.generateKeyPair();
      
      // Create keys directory if it doesn't exist
      privateKeyFile.getParentFile().mkdirs();
      
      // Save private key in PKCS#8 DER format
      try (java.io.FileOutputStream fos = new java.io.FileOutputStream(privateKeyFile)) {
        fos.write(keyPair.getPrivate().getEncoded());
      }
      
      // Save public key in X.509 DER format
      try (java.io.FileOutputStream fos = new java.io.FileOutputStream(publicKeyFile)) {
        fos.write(keyPair.getPublic().getEncoded());
      }
      
      // Set permissions
      privateKeyFile.setReadable(true, true);
      privateKeyFile.setWritable(true, true);
      publicKeyFile.setReadable(true, false);
      
      System.out.println(" Database keys generated successfully");
    } catch (Exception e) {
      System.err.println("ERROR: Failed to generate database keys: " + e.getMessage());
      e.printStackTrace();
      System.exit(1);
    }
  }
}
