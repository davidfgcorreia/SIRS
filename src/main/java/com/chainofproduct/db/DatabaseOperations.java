package com.chainofproduct.db;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DatabaseOperations {
    private static final String DB_URL = "jdbc:postgresql://localhost:5432/server-name";
    private static final String ADMIN_USER = "server-name";
    private static final String ADMIN_PASSWORD = "password";

    public static void insertTransaction(long id, long timestamp, String seller, String buyer, String product, long units, long amount) throws SQLException {
        String sql = "INSERT INTO transaction (id, timestamp, seller, buyer, product, units, amount) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING";
        try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setLong(1, id);
            pstmt.setLong(2, timestamp);
            pstmt.setString(3, seller);
            pstmt.setString(4, buyer);
            pstmt.setString(5, product);
            pstmt.setLong(6, units);
            pstmt.setLong(7, amount);
            pstmt.executeUpdate();
        }
    }

    public static void addShare(long transactionId, String share, String sharedBy) throws SQLException {
        String sql = "INSERT INTO transaction_shares (id, share, shared_by) VALUES (?, ?, ?) ON CONFLICT DO NOTHING";
        try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setLong(1, transactionId);
            pstmt.setString(2, share);
            pstmt.setString(3, sharedBy); // 'seller' or 'buyer'
            pstmt.executeUpdate();
        }
    }

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

    public static List<TransactionRecord> getAllTransactions() throws SQLException {
        String sql = "SELECT * FROM transaction";
        List<TransactionRecord> transactions = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                transactions.add(new TransactionRecord(
                    rs.getLong("id"),
                    rs.getLong("timestamp"),
                    rs.getString("seller"),
                    rs.getString("buyer"),
                    rs.getString("product"),
                    rs.getLong("units"),
                    rs.getLong("amount")
                ));
            }
        }
        return transactions;
    }

    public static TransactionRecord getTransactionById(long id) throws SQLException {
        String sql = "SELECT * FROM transaction WHERE id = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setLong(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new TransactionRecord(
                        rs.getLong("id"),
                        rs.getLong("timestamp"),
                        rs.getString("seller"),
                        rs.getString("buyer"),
                        rs.getString("product"),
                        rs.getLong("units"),
                        rs.getLong("amount")
                    );
                }
            }
        }
        return null;
    }

    // TransactionRecord inner class for returning transaction data
    public static class TransactionRecord {
        public final long id;
        public final long timestamp;
        public final String seller;
        public final String buyer;
        public final String product;
        public final long units;
        public final long amount;

        public TransactionRecord(long id, long timestamp, String seller, String buyer, String product, long units, long amount) {
            this.id = id;
            this.timestamp = timestamp;
            this.seller = seller;
            this.buyer = buyer;
            this.product = product;
            this.units = units;
            this.amount = amount;
        }
    }
}
