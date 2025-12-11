package com.chainofproduct.db;

import java.sql.SQLException;

import com.chainofproduct.db.DatabaseOperations.DestinationInfo;
import com.chainofproduct.db.DatabaseOperations.TransactionRecord;
import com.chainofproduct.utils.ApiCalls.ServerExecutor;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.util.List;

import java.util.Arrays;
import java.util.ArrayList;

public class ServerExecutorImpl implements ServerExecutor {

  /*
   * I assumed that the request is a jsonHeader, and that the sql query is in the
   * jsonHeader
   * If not, make it that way cause its easier
   * Alright I've been thinking...
   * a server sends a number that represents the query we gonna execute on
   * database
   * in this case, 0 is the first one in DatabaseOperation, incrementing by order
   * of functions
   * that appear there.
   */
  private static List<byte[]> extractJsonObjects(byte[] data) {
    List<byte[]> result = new ArrayList<>();
    int start = -1;
    int count = 0;

    for (int i = 0; i < data.length; i++) {
      byte b = data[i];

      if (b == '{') {
        start = i;
        if (count == 1) {
          result.add(Arrays.copyOfRange(data, i, data.length));
          return result;
        }

      } else if (b == '}') {
        count++;
        if (start != -1) {
          // Extract the jsonHeader object as raw bytes
          result.add(Arrays.copyOfRange(data, start, i + 1));
        }
      }
    }

    return result;
  }

  @Override
  public byte[] execute(byte[] request) throws Exception {

    List<byte[]> data = extractJsonObjects(request);

    ObjectMapper mapper = new ObjectMapper();

    byte[] header = data.get(0);
    JsonNode jsonHeader = mapper.readTree(header);

    int sql = jsonHeader.get("sql").asInt();

    long id;
    String seller;
    String buyer;

    long transactionId;
    String share;
    String sharedBy;

    String companyName;

    String ip;
    int port;
    String publicKey;

    String name, leader, source, destination;

    List<String> additions, removals;

    switch (sql) {
      case 0:
        byte[] binaryData = data.get(1);
        id = jsonHeader.get("id").asInt();
        source = jsonHeader.get("source").asText();
        destination = jsonHeader.get("destination").asText();
        seller = jsonHeader.get("seller").asText();
        buyer = jsonHeader.get("buyer").asText();
        String sellerOrBuyer = source.equals(seller) ? "seller" : "buyer";
        try {
          DatabaseOperations.insertTransaction(id, seller, buyer, binaryData);
          DatabaseOperations.addShare(id, seller, "seller", seller);
          DatabaseOperations.addShare(id, buyer, "buyer", buyer);
          DatabaseOperations.addShare(id, destination, sellerOrBuyer, source);
          return null;
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 1: // FIXME: legacy code, cause its not used anymore
        transactionId = jsonHeader.get("transactionId").asInt();
        share = jsonHeader.get("share").asText();
        sharedBy = jsonHeader.get("sharedBy").asText();
        try {
          DatabaseOperations.addShare(transactionId, share, "seller", sharedBy);
          return null;
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 2:
        transactionId = jsonHeader.get("transactionId").asInt();
        try {
          List<String> shares = DatabaseOperations.getShares(transactionId);
          return mapper.writeValueAsBytes(shares);
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 3:
        transactionId = jsonHeader.get("transactionId").asInt();
        sharedBy = jsonHeader.get("sharedBy").asText();
        try {
          List<String> shares = DatabaseOperations.getSharesBySharedBy(transactionId, sharedBy);
          return mapper.writeValueAsBytes(shares);
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 4:
        try {
          List<TransactionRecord> transactions = DatabaseOperations.getAllTransactions();
          return mapper.writeValueAsBytes(transactions);
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 5:
        id = jsonHeader.get("id").asInt();
        try {
          TransactionRecord transactions = DatabaseOperations.getTransactionById(id);
          return mapper.writeValueAsBytes(transactions);
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 6:
        companyName = jsonHeader.get("companyName").asText();
        try {
          DestinationInfo dest = DatabaseOperations.getDestinationInfo(companyName);
          return mapper.writeValueAsBytes(dest);
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 7:
        companyName = jsonHeader.get("companyName").asText();
        ip = jsonHeader.get("ip").asText();
        port = jsonHeader.get("port").asInt();
        publicKey = jsonHeader.get("publicKey").asText();
        try {
          DatabaseOperations.addDestination(companyName, ip, port, publicKey);
          return null;
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 8:
        name = jsonHeader.get("name").asText();
        leader = jsonHeader.get("leader").asText();
        try {
          DatabaseOperations.addGroup(name, leader);
          return null;
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 9:
        name = jsonHeader.get("name").asText();
        try {
          DatabaseOperations.getGroupLeader(name);
          return null;
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 10:
        name = jsonHeader.get("name").asText();
        additions = mapper.readValue(jsonHeader.get("additions").asText(), new TypeReference<List<String>>() {
        });
        try {
          DatabaseOperations.addGroupElements(name, additions);
          return null;
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 11:
        name = jsonHeader.get("name").asText();
        removals = mapper.readValue(jsonHeader.get("removals").asText(), new TypeReference<List<String>>() {
        });
        try {
          DatabaseOperations.removeGroupElements(name, removals);
          return null;
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 12:
        name = jsonHeader.get("name").asText();
        try {
          DatabaseOperations.getGroupMembers(name);
          return null;
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      default:
        // unrecognizable command (sql)
        System.err.println("unrecognizable command");
        return "unrecognizable command".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
  }
}
