package com.chainofproduct.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class DatabaseInitializer {
  private static final String DB_URL = "jdbc:postgresql://localhost:5432/server-name";
  private static final String ADMIN_USER = "server-name";
  private static final String ADMIN_PASSWORD = "password";

    public static void initializeDatabase() throws SQLException {
        try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
             Statement stmt = conn.createStatement()) {
            // Create transaction table
            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS transaction (" +
                "id BIGINT PRIMARY KEY," +
                "timestamp BIGINT NOT NULL," +
                "seller VARCHAR(255) NOT NULL," +
                "buyer VARCHAR(255) NOT NULL," +
                "product VARCHAR(255) NOT NULL," +
                "units BIGINT NOT NULL," +
                "amount BIGINT NOT NULL" +
                ")"
            );
            // Create transaction_shares table
                stmt.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS transaction_shares (" +
                    "id BIGINT NOT NULL," +
                    "share VARCHAR(255) NOT NULL," +
                    "shared_by VARCHAR(16) NOT NULL," + // 'seller' or 'buyer'
                    "PRIMARY KEY (id, share)," +
                    "FOREIGN KEY (id) REFERENCES transaction(id) ON DELETE CASCADE" +
                    ")"
                );
            // Create destination_ips table
            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS destination_ips (" +
                "company VARCHAR(255) PRIMARY KEY," +
                "ip VARCHAR(32) NOT NULL," +
                "port INTEGER NOT NULL," +
                "public_key TEXT NOT NULL" +
                ")"
            );
            // Create share_propagation table to track share forwarding
            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS share_propagation (" +
                "id SERIAL PRIMARY KEY," +
                "transaction_id BIGINT NOT NULL," +
                "destination VARCHAR(255) NOT NULL," +
                "origin VARCHAR(255) NOT NULL," +
                "timestamp BIGINT NOT NULL," +
                "FOREIGN KEY (transaction_id) REFERENCES transaction(id) ON DELETE CASCADE" +
                ")"
            );
            System.out.println("Database and tables initialized successfully.");
        }
    }

  public static void main(String[] args) {
    try {
      initializeDatabase();
    } catch (SQLException | IOException e) {
      System.err.println("Database initialization failed: " + e.getMessage());
      e.printStackTrace();
    }
  }
}
