package com.chainofproduct.server;

import java.sql.SQLException;
import java.util.concurrent.BlockingQueue;
import com.chainofproduct.db.DatabaseOperations;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ServerOperations {
  private final BlockingQueue<Request> sendQueue;
  private final Object sendLock;

  public ServerOperations(BlockingQueue<Request> sendQueue, Object sendLock) {
    this.sendQueue = sendQueue;
    this.sendLock = sendLock;
  }

  // Handles a send transaction request: resolves destination, prepares arguments,
  // queues request, and handles DB logic
  public boolean handleSendTransaction(String dataFile, String destination) {
    // TODO: Resolve destination, obtain all needed arguments for the request
    // TODO: Add share request, place file in DB, and add share in DB after
    // confirmation
    // For now, just return true as a stub

    // need to send to the destination the info; I think i need to create a proto
    // file to send the transaction to the seller

    ObjectMapper mapper = new ObjectMapper();
    try {
      JsonNode node = mapper.readTree(dataFile);
      DatabaseOperations.insertTransaction(node.get("id").asInt(), node.get("timestamp").asInt(),
          node.get("seller").asText(), node.get("buyer").asText(), node.get("product").asText(),
          node.get("units").asInt(), node.get("amount").asInt());
    } catch (JsonProcessingException | SQLException e) {
      // do something
      return false;
    }

    try {
      JsonNode node = mapper.readTree(dataFile);

      DatabaseOperations.addShare(node.get("id").asInt(), node.get("seller").asText(), "buyer");
      DatabaseOperations.addShare(node.get("id").asInt(), node.get("buyer").asText(), "buyer");
    } catch (JsonProcessingException | SQLException e) {
      // do something
      return false;
    }

    return true;
  }

  // Called to handle a transaction request
  public void handleTransactionRequest(Request req) {
    // TODO: Add request to queue and notify sender manager
    try {
      this.sendQueue.put(req);
    } catch (InterruptedException e) {
      // do nothing
    }
  }

  // Called to handle a share request
  public void handleShareRequest(Request req) {
    // TODO: Add request to queue and notify sender manager
    try {
      this.sendQueue.put(req);
    } catch (InterruptedException e) {
      // do nothing
    }

  }

  // Handles a receive transaction request (placeholder)
  public void handleReceiveTransaction(/* add needed parameters */) {
    // TODO: Implement logic to process a received transaction
  }

  // Handles a receive share request (placeholder)
  public void handleReceiveShare(/* add needed parameters */) {
    // TODO: Implement logic to process a received share
  }

}
