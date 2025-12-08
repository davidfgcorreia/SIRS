package com.chainofproduct.db;

import com.chainofproduct.db.DatabaseOperations.DestinationInfo;
import com.chainofproduct.db.DatabaseOperations.TransactionRecord;
import com.chainofproduct.utils.*;
import org.junit.BeforeClass;
import org.junit.After;
import org.junit.Test;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.List;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyBoolean;

public class DatabaseTest {

  public static byte[] tcpRequest(byte[] dataFile) {
    String host = "127.0.0.1";
    int port = 6767;
    String entityType = "server";
    int clientNum = 67;
    String receiverEntity = "db";
    try {
      return ApiCalls.actAsSender(host, port, entityType, clientNum, receiverEntity, dataFile);
    } catch (Exception e) {
      // do something
    }
    return "ERROR".getBytes(java.nio.charset.StandardCharsets.UTF_8);
  }

  @Test
  public void testAddTransaction() throws Exception {
    byte[] dataFile;
    String fileContent = "\"sql\":0\n{\"id\":123,\"timestamp\":17663363400,\"seller\":\"client42\",\"buyer\":\"destination42\",\"product\":\"Indium\",\"units\":40000,\"amount\":90000000}";

    java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("testtransaction", ".json");
    java.nio.file.Files.write(tempFile, fileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    dataFile = tempFile.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] response = tcpRequest(dataFile);
    assertEquals(response, null);
  }

  @Test
  public void testAddShare() throws Exception {
    byte[] dataFile;
    String fileContent = "\"sql\":1\n{\"transactionId\":123,\"share\":\"destination42\", \"sharedBy\":seller}";

    java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("testshare", ".json");
    java.nio.file.Files.write(tempFile, fileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    dataFile = tempFile.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] response = tcpRequest(dataFile);
    assertEquals(response, null);
  }

  @Test
  public void testGetShares() throws Exception {
    byte[] dataFile;
    String fileContent = "\"sql\":2\n{\"transactionId\":123}";
    ObjectMapper mapper = new ObjectMapper();
    List<String> expected = Arrays.asList("destination42");

    java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("testshares", ".json");
    java.nio.file.Files.write(tempFile, fileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    dataFile = tempFile.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] response = tcpRequest(dataFile);
    List<String> shares = mapper.readValue(response, new TypeReference<List<String>>() {
    });

    assertEquals(shares, expected);
  }

  @Test
  public void testGetSharesBySharesBy() throws Exception {
    byte[] dataFile;
    String fileContent = "\"sql\":3\n{\"transactionId\":123, \"sharedBy\":seller}";
    ObjectMapper mapper = new ObjectMapper();
    List<String> expected = Arrays.asList("destination42");

    java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("testshares", ".json");
    java.nio.file.Files.write(tempFile, fileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    dataFile = tempFile.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] response = tcpRequest(dataFile);
    List<String> shares = mapper.readValue(response, new TypeReference<List<String>>() {
    });

    assertEquals(shares, expected);

  }

  @Test
  public void testGetAllTransactions() throws Exception {
    byte[] dataFile;
    String fileContent = "\"sql\":4\n";

    String expectedFileContent = "\"sql\":0\n{\"id\":123,\"timestamp\":17663363400,\"seller\":\"client42\",\"buyer\":\"destination42\",\"product\":\"Indium\",\"units\":40000,\"amount\":90000000}";

    java.nio.file.Path tempFile2 = java.nio.file.Files.createTempFile("testtransaction2", ".json");
    java.nio.file.Files.write(tempFile2, expectedFileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    byte[] rawdata = tempFile2.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);

    ObjectMapper mapper = new ObjectMapper();
    List<TransactionRecord> expected = new ArrayList<>();
    expected.add(new TransactionRecord(123, 17663363400L, "client42", "destination42", rawdata));

    java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("testtransaction1", ".json");
    java.nio.file.Files.write(tempFile, fileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    dataFile = tempFile.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] response = tcpRequest(dataFile);
    List<TransactionRecord> transactions = mapper.readValue(response, new TypeReference<List<TransactionRecord>>() {
    });

    assertEquals(transactions, expected);
  }

  @Test
  public void testGetTransactionById() throws Exception {
    byte[] dataFile;
    String fileContent = "\"sql\":5\n{\"id\":123}";

    String expectedFileContent = "\"sql\":0\n{\"id\":123,\"timestamp\":17663363400,\"seller\":\"client42\",\"buyer\":\"destination42\",\"product\":\"Indium\",\"units\":40000,\"amount\":90000000}";

    java.nio.file.Path tempFile2 = java.nio.file.Files.createTempFile("testtransaction2", ".json");
    java.nio.file.Files.write(tempFile2, expectedFileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    byte[] rawdata = tempFile2.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);

    ObjectMapper mapper = new ObjectMapper();

    TransactionRecord expected = new TransactionRecord(123, 17663363400L, "client42", "destination42", rawdata);

    java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("testtransaction1", ".json");
    java.nio.file.Files.write(tempFile, fileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    dataFile = tempFile.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] response = tcpRequest(dataFile);
    TransactionRecord transactions = mapper.readValue(response, TransactionRecord.class); // bytes → JSON → object

    assertEquals(transactions, expected);
  }

  @Test
  public void testAddDestination() throws Exception {
    byte[] dataFile;
    String fileContent = "\"sql\":7\n{\"companyName\":\"client42\",\"ip\":\"127.0.1.1\",\"port\":6767,\"publicKey\":\"key\"}";

    java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("testdestination", ".json");
    java.nio.file.Files.write(tempFile, fileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    dataFile = tempFile.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);

    byte[] response = tcpRequest(dataFile);

    assertEquals(response, null);

  }

  @Test
  public void testGetDestinationInfo() throws Exception {
    byte[] dataFile;
    String fileContent = "\"sql\":6\n{\"companyName\":\"client42\"}";
    ObjectMapper mapper = new ObjectMapper();

    java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("testdestination", ".json");
    java.nio.file.Files.write(tempFile, fileContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    dataFile = tempFile.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);

    DestinationInfo expected = new DestinationInfo("client42", "127.0.1.1", 6767, "key");

    byte[] response = tcpRequest(dataFile);
    DestinationInfo destination = mapper.readValue(response, DestinationInfo.class); // bytes → JSON → object

    assertEquals(destination, expected);
  }
}
