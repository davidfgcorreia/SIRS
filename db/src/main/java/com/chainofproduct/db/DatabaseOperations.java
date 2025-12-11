package com.chainofproduct.db;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DatabaseOperations {
  private static final String DB_URL = "jdbc:postgresql://localhost:5432/ChainOfProduct";
  private static final String ADMIN_USER = "ChainOfProduct_admin";
  private static final String ADMIN_PASSWORD = "TheMostSecurePasswordInTheHistoryOfPasswords";

  // sql:0
  // id, source, dest, group(boolean), seller, buyer, raw file
  public static void insertTransaction(long id, String seller, String buyer, byte[] raw_file)
      throws SQLException {
    String sql = "INSERT INTO transaction (id, seller, buyer, raw_file) VALUES (?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING";
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setLong(1, id);
      pstmt.setString(2, seller);
      pstmt.setString(3, buyer);
      pstmt.setBytes(4, raw_file);
      pstmt.executeUpdate();
    }
  }

  // sql:1
  public static void addShare(long transactionId, String share, String sharedBy, String sharedName)
      throws SQLException {
    String sql = "INSERT INTO transaction_shares (id, share, shared_by, shared_name) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING";
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setLong(1, transactionId);
      pstmt.setString(2, share);
      pstmt.setString(3, sharedBy); // 'seller' or 'buyer'
      pstmt.setString(4, sharedName);
      pstmt.executeUpdate();
    }
  }

  // sql:2
  public static List<String> getShares(long transactionId) throws SQLException {
    String sql = "SELECT share FROM transaction_shares WHERE id = ?";
    List<String> shares = new ArrayList<>();
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setLong(1, transactionId);
      try (ResultSet rs = pstmt.executeQuery()) {
        while (rs.next()) {
          shares.add(rs.getString("share"));
        }
      }
    }
    return shares;
  }

  // sql:3
  public static List<String> getSharesBySharedBy(long transactionId, String sharedBy) throws SQLException {
    String sql = "SELECT share FROM transaction_shares WHERE id = ? AND shared_by = ?";
    List<String> shares = new ArrayList<>();
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setLong(1, transactionId);
      pstmt.setString(2, sharedBy); // 'seller' or 'buyer'
      try (ResultSet rs = pstmt.executeQuery()) {
        while (rs.next()) {
          shares.add(rs.getString("share"));
        }
      }
    }
    return shares;
  }

  // sql:4
  public static List<TransactionRecord> getAllTransactions() throws SQLException {
    String sql = "SELECT * FROM transaction";
    List<TransactionRecord> transactions = new ArrayList<>();
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql)) {
      while (rs.next()) {
        transactions.add(new TransactionRecord(
            rs.getLong("id"),
            rs.getString("seller"),
            rs.getString("buyer"),
            rs.getBytes("raw_file")));
      }
    }
    return transactions;
  }

  // sql:5
  public static TransactionRecord getTransactionById(long id) throws SQLException {
    String sql = "SELECT * FROM transaction WHERE id = ?";
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setLong(1, id);
      try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
          return new TransactionRecord(
              rs.getLong("id"),
              rs.getString("seller"),
              rs.getString("buyer"),
              rs.getBytes("raw_file"));
        }
      }
    }
    return null;
  }

  /**
   * Get destination information (IP, port, public key) for a company name.
   * Returns null if company not found. sql:6
   */
  public static DestinationInfo getDestinationInfo(String companyName) throws SQLException {
    String sql = "SELECT ip, port, public_key FROM destination_ips WHERE company = ?";
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, companyName);
      try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
          return new DestinationInfo(
              companyName,
              rs.getString("ip"),
              rs.getInt("port"),
              rs.getString("public_key"));
        }
      }
    }
    return null;
  }

  /**
   * Add a company to the destination_ips table.
   * For future purpose? sql:7
   */
  public static void addDestination(String companyName, String ip, int port, String publicKey) throws SQLException {
    String sql = "INSERT INTO destination_ips (company, ip, port, public_key) VALUES (?, ?, ?, ?) ON CONFLICT (company) DO UPDATE SET ip = ?, port = ?, public_key = ?";
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, companyName);
      pstmt.setString(2, ip);
      pstmt.setInt(3, port);
      pstmt.setString(4, publicKey);
      pstmt.setString(5, ip);
      pstmt.setInt(6, port);
      pstmt.setString(7, publicKey);
      pstmt.executeUpdate();
    }
  }

  // sql:8
  public static void addGroup(String name, String leader) throws SQLException {
    String sql = "INSERT INTO groups (name, leader) VALUES (?, ?) ON CONFLICT (name) DO NOTHING";
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, name);
      pstmt.setString(2, leader);
    }
  }

  // sql:9
  public static String getGroupLeader(String name) throws SQLException {
    String sql = "SELECT leader FROM groups WHERE name = ?";
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, name);

      try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
          return rs.getString("leader");
        }
      }
    }
    return null;
  }

  // sql:10
  public static void addGroupElements(String name, List<String> additions) throws SQLException {
    String sql = "INSERT INTO group_members (name, company) VALUES (?, ?)";
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      for (String addition : additions) {
        pstmt.setString(1, name);
        pstmt.setString(2, addition);
        pstmt.addBatch();
      }
      pstmt.executeBatch();
    }
  }

  // sql:11
  public static void removeGroupElements(String name, List<String> removals) throws SQLException {
    String sql = "DELETE FROM group_members WHERE name = ? AND company = ?";
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      for (String removal : removals) {
        pstmt.setString(1, name);
        pstmt.setString(2, removal);
        pstmt.addBatch();
      }
      pstmt.executeBatch();
    }
  }

  // sql:12
  public static List<String> getGroupMembers(String name) throws SQLException {
    String sql = "SELECT company FROM group_members WHERE name = ?";
    List<String> response = new ArrayList<>();
    try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, name);

      try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
          response.add(rs.getString("company"));
        }
      }
    }
    return response;
  }

  // TransactionRecord inner class for returning transaction data
  public static class TransactionRecord {
    public final long id;
    public final String seller;
    public final String buyer;
    public final byte[] raw_file;

    public TransactionRecord(long id, String seller, String buyer, byte[] raw_file) {
      this.id = id;
      this.seller = seller;
      this.buyer = buyer;
      this.raw_file = raw_file;
    }
  }

  // DestinationInfo inner class for returning destination data
  public static class DestinationInfo {
    public final String company;
    public final String ip;
    public final int port;
    public final String publicKey;

    public DestinationInfo(String company, String ip, int port, String publicKey) {
      this.company = company;
      this.ip = ip;
      this.port = port;
      this.publicKey = publicKey;
    }
  }
}
