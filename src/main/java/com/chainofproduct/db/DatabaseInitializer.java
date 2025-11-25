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

  public static void initializeDatabase() throws SQLException, IOException {
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        Statement stmt = conn.createStatement()) {
      // Read the SQL file into a string
      String sql = new String(Files.readAllBytes(Paths.get("populate.sql")));

      // Split by semicolon if multiple statements
      for (String query : sql.split(";")) {
        if (!query.trim().isEmpty()) {
          stmt.execute(query);
        }
      }
      System.out.println("SQL file executed successfully!");
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
