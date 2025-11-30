package com.chainofproduct.db;

import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

import com.chainofproduct.db.DatabaseOperations.DestinationInfo;
import com.chainofproduct.db.DatabaseOperations.TransactionRecord;
import com.chainofproduct.utils.ApiCalls.ServerExecutor;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;

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
    String jsonString = new String(request, StandardCharsets.UTF_8);
    ObjectMapper mapper = new ObjectMapper();
    JsonNode json = mapper.readTree(jsonString);
    String response;

    int sql = json.get("sql").asInt();
    long id;
    long timestamp;
    String seller;
    String buyer;
    String product;
    long units;
    long amount;

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
        product = json.get("product").asText();
        units = json.get("units").asInt();
        amount = json.get("amount").asInt();
        try {
          DatabaseOperations.insertTransaction(id, timestamp, seller, buyer, product, units, amount);
        } catch (SQLException e) {
          // do something
        }
        response = "New transaction inserted in database!"; // FIXME: should it be no response?
        return response.getBytes(StandardCharsets.UTF_8);

      case 1:
        transactionId = json.get("transactionId").asInt();
        share = json.get("share").asText();
        sharedBy = json.get("sharedBy").asText();
        try {
          DatabaseOperations.addShare(transactionId, share, sharedBy);
        } catch (SQLException e) {
          // do something
        }
        response = "New share inserted in database!";
        return response.getBytes(StandardCharsets.UTF_8);

      case 2:
        transactionId = json.get("transactionId").asInt();
        try {
          List<String> shares = DatabaseOperations.getShares(transactionId);
          return mapper.writeValueAsBytes(shares);
        } catch (SQLException e) {
          // do smoething
        }
        break;

      case 3:
        transactionId = json.get("transactionId").asInt();
        sharedBy = json.get("sharedBy").asText();
        try {
          List<String> shares = DatabaseOperations.getSharesBySharedBy(transactionId, sharedBy);
          return mapper.writeValueAsBytes(shares);
        } catch (SQLException e) {
          // do something
        }
        break;

      case 4:
        try {
          List<TransactionRecord> transactions = DatabaseOperations.getAllTransactions();
          return mapper.writeValueAsBytes(transactions);
        } catch (SQLException e) {
          // do something
        }
        break;

      case 5:
        id = json.get("id").asInt();
        try {
          TransactionRecord transactions = DatabaseOperations.getTransactionById(id);
          return mapper.writeValueAsBytes(transactions);
        } catch (SQLException e) {
          // do something
        }
        break;

      case 6:
        companyName = json.get("companyName").asText();
        try {
          DestinationInfo destination = DatabaseOperations.getDestinationInfo(companyName);
          return mapper.writeValueAsBytes(destination);
        } catch (SQLException e) {
          // do something
        }
        break;

      case 7:
        companyName = json.get("companyName").asText();
        try {
          DestinationInfo destination = DatabaseOperations.getDestinationInfo(companyName);
          return mapper.writeValueAsBytes(destination);
        } catch (SQLException e) {
          // do something
        }
        break;

      case 8:
        companyName = json.get("companyName").asText();
        ip = json.get("ip").asText();
        port = json.get("port").asInt();
        publicKey = json.get("publicKey").asText();
        try {
          DatabaseOperations.addDestination(companyName, ip, port, publicKey);
        } catch (SQLException e) {
          // do something
        }
        response = "New destination inserted in database!";
        return response.getBytes(StandardCharsets.UTF_8);

      default:
        // unrecognizable command (sql)
        break;
    }
    return null;
  }
}
