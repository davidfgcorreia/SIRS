package com.chainofproduct.db;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DatabaseOperations {
    private static final String DB_URL = "jdbc:postgresql://localhost:5432/server-name";
    private static final String ADMIN_USER = "server-name";
    private static final String ADMIN_PASSWORD = "password";
    
    // Server identity - should be configured based on which server this is
    private static String SERVER_NAME = "Lays Chips"; // Default, should be configurable
    
    public static void setServerName(String name) {
        SERVER_NAME = name;
    }
    
    public static String getServerName() {
        return SERVER_NAME;
    }

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

    /**
     * Get destination information (IP, port, public key) for a company name.
     * Returns null if company not found.
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
                        rs.getString("public_key")
                    );
                }
            }
        }
        return null;
    }
    
    /**
     * Check if a party (buyer/seller) has sufficient shares for a transaction.
     * Returns true if the party has at least 'requiredAmount' shares.
     */
    public static boolean checkShares(long transactionId, String party, int requiredAmount) throws SQLException {
        String sql = "SELECT COUNT(*) FROM transaction_shares WHERE id = ? AND shared_by = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setLong(1, transactionId);
            pstmt.setString(2, party);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    int count = rs.getInt(1);
                    return count >= requiredAmount;
                }
            }
        }
        return false;
    }
    
    /**
     * Store share propagation information.
     * Logs when shares are forwarded to another destination.
     */
    public static void storeSharePropagation(long transactionId, String destination, String origin) throws SQLException {
        String sql = "INSERT INTO share_propagation (transaction_id, destination, origin, timestamp) VALUES (?, ?, ?, ?)";
        try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setLong(1, transactionId);
            pstmt.setString(2, destination);
            pstmt.setString(3, origin);
            pstmt.setLong(4, System.currentTimeMillis());
            pstmt.executeUpdate();
        }
    }
    
    /**
     * Add a company to the destination_ips table.
     * For future purpose?
     */
    public static void addDestination(String company, String ip, int port, String publicKey) throws SQLException {
        String sql = "INSERT INTO destination_ips (company, ip, port, public_key) VALUES (?, ?, ?, ?) ON CONFLICT (company) DO UPDATE SET ip = ?, port = ?, public_key = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, ADMIN_USER, ADMIN_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, company);
            pstmt.setString(2, ip);
            pstmt.setInt(3, port);
            pstmt.setString(4, publicKey);
            pstmt.setString(5, ip);
            pstmt.setInt(6, port);
            pstmt.setString(7, publicKey);
            pstmt.executeUpdate();
        }
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
