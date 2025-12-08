package com.chainofproduct.db;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.sql.SQLException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.chainofproduct.utils.ApiCalls;

public class DatabaseMain {

  private static final int TLS_PORT = 6767;
  private static final String KEYSTORE = "db-keystore.p12";
  private static final String KEYSTORE_PASSWORD = "changeit";

  public static void main(String[] args) {

    try {
      DatabaseInitializer.initializeDatabase();
    } catch (SQLException | IOException e) {
      System.err.println("Error initializing database: " + e.getMessage());
      e.printStackTrace();
    }
    // TODO: add a way to decide to populate or not the db
    try {

      KeyStore ks = KeyStore.getInstance("p12");
      try (FileInputStream fis = new FileInputStream(KEYSTORE)) {
        ks.load(fis, KEYSTORE_PASSWORD.toCharArray());
      }
      KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
      kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(kmf.getKeyManagers(), null, new java.security.SecureRandom());
      javax.net.ssl.SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
      javax.net.ssl.SSLServerSocket serverSocket = (javax.net.ssl.SSLServerSocket) ssf.createServerSocket(TLS_PORT);

      System.out.println("DB Server listening on port " + TLS_PORT + " (TLS)");
      java.util.concurrent.ExecutorService receiverPool = java.util.concurrent.Executors.newFixedThreadPool(10);
      while (true) {
        final javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) serverSocket.accept();
        ServerExecutorImpl executor = new ServerExecutorImpl();
        receiverPool.submit(() -> {
          try {
            ApiCalls.handleClient(socket, executor);
          } catch (Exception e) {
            e.printStackTrace();
          }
        });
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
