package com.chainofproduct.db;

import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

import com.chainofproduct.db.DatabaseOperations.DestinationInfo;
import com.chainofproduct.db.DatabaseOperations.TransactionRecord;
import com.chainofproduct.utils.ApiCalls.ServerExecutor;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Arrays;

public class ServerExecutorImpl implements ServerExecutor {

  /*
   * I assumed that the request is a json, and that the sql query is in the json
   * If not, make it that way cause its easier
   * Alright I've been thinking...
   * a server sends a number that represents the query we gonna execute on
   * database
   * in this case, 0 is the first one in DatabaseOperation, incrementing by order
   * of functions
   * that appear there.
   */
  @Override
  public byte[] execute(byte[] request) throws Exception {

    int newlineIndex = -1;
    for (int i = 0; i < request.length; i++) { // before the binary, sql:<number>\n needs to exist
      if (request[i] == '\n') { // ASCII 10
        newlineIndex = i;
        break;
      }
    }
    if (newlineIndex == -1) {
      throw new IllegalStateException("No newline delimiter found!");
    }

    // Step 2: Extract header text
    String header = new String(Arrays.copyOfRange(request, 0, newlineIndex),
        StandardCharsets.UTF_8);
    int sql = Integer.parseInt(header.split(":")[1]);

    byte[] binaryData = Arrays.copyOfRange(request, newlineIndex + 1, request.length);
    String text = new String(binaryData, StandardCharsets.UTF_8);

    int endIndex = text.indexOf("}") + 1;
    String jsonString = text.substring(newlineIndex, endIndex);

    // String jsonString = new String(request, StandardCharsets.UTF_8);
    ObjectMapper mapper = new ObjectMapper();
    JsonNode json = mapper.readTree(jsonString);

    long id;
    long timestamp;
    String seller;
    String buyer;

    long transactionId;
    String share;
    String sharedBy;

    String companyName;

    String ip;
    int port;
    String publicKey;

    switch (sql) {
      case 0:
        id = json.get("id").asInt();
        timestamp = json.get("timestamp").asInt();
        seller = json.get("seller").asText();
        buyer = json.get("buyer").asText();
        try {
          DatabaseOperations.insertTransaction(id, timestamp, seller, buyer, binaryData);
          return null;
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 1:
        transactionId = json.get("transactionId").asInt();
        share = json.get("share").asText();
        sharedBy = json.get("sharedBy").asText();
        try {
          DatabaseOperations.addShare(transactionId, share, sharedBy);
          return null;
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 2:
        transactionId = json.get("transactionId").asInt();
        try {
          List<String> shares = DatabaseOperations.getShares(transactionId);
          return mapper.writeValueAsBytes(shares);
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 3:
        transactionId = json.get("transactionId").asInt();
        sharedBy = json.get("sharedBy").asText();
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
        id = json.get("id").asInt();
        try {
          TransactionRecord transactions = DatabaseOperations.getTransactionById(id);
          return mapper.writeValueAsBytes(transactions);
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 6:
        companyName = json.get("companyName").asText();
        try {
          DestinationInfo destination = DatabaseOperations.getDestinationInfo(companyName);
          return mapper.writeValueAsBytes(destination);
        } catch (SQLException e) {
          System.err.println("There was a problem realizing the sql query: " + e.getMessage());
          e.printStackTrace();
          return "An error has occured".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

      case 7:
        companyName = json.get("companyName").asText();
        ip = json.get("ip").asText();
        port = json.get("port").asInt();
        publicKey = json.get("publicKey").asText();
        try {
          DatabaseOperations.addDestination(companyName, ip, port, publicKey);
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
