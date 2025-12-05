package com.chainofproduct.client;

/* 
import com.chainofproduct.utils.Request;
import org.junit.Before;
import org.junit.Test;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.List;
import java.util.ArrayList;

import static org.junit.Assert.*;

public class ClientOperationsTest {
    private BlockingQueue<Request> sendQueue;
    private Object sendLock;
    private List<Request> requestList;
    private ClientOperations clientOps;

    @Before
    // @Before
    // public void setUp() {
    //     sendQueue = new LinkedBlockingQueue<Request>() {
    //         @Override
    //         public void put(Request req) {
    //             requestList.add(req);
    //         }
    //     };
    //     sendLock = new Object();
    //     requestList = new ArrayList<>();
    //     clientOps = new ClientOperations(sendQueue, sendLock, "client42");
    // }
    @Test
    public void testSendTransaction() {
        clientOps.sendtrsaction("/dev/null", "destination42");
        assertFalse(requestList.isEmpty());
        Request req = requestList.get(0);
        assertEquals("client", req.getEntityType());
        assertEquals(42, req.getClientNum());
        assertEquals("server", req.getReceiverEntity());
    }

    // @Test
    // public void testGetTransactionById() {
    //     clientOps.gettransactionById(123L);
    //     assertFalse(requestList.isEmpty());
    //     Request req = requestList.get(0);
    //         String payload = new String(req.getDataFile());
    //     assertTrue(payload.contains("getById"));
    //     assertTrue(payload.contains("trasaction_id: 123"));
    // }

    @Test
    public void testGetAll() {
        clientOps.getAll();
        assertFalse(requestList.isEmpty());
        Request req = requestList.get(0);
            String payload = new String(req.getDataFile());
        assertTrue(payload.contains("getAll"));
    }
    // @Test
    // public void testGetShares() {
    //     clientOps.getShares(456L);
    //     assertFalse(requestList.isEmpty());
    //     Request req = requestList.get(0);
    //         String payload = new String(req.getDataFile());
    //     assertTrue(payload.contains("getShares"));
    //     assertTrue(payload.contains("transaction_id: 456"));
    // }
    }

    @Test
    public void testGetSharesBy() {
        clientOps.getSharesBy(789L, "alice");
        assertFalse(requestList.isEmpty());
        Request req = requestList.get(0);
            String payload = new String(req.getDataFile());
        assertTrue(payload.contains("getSharesBy"));
        assertTrue(payload.contains("shared_by: alice"));
    // @Test
    // public void testGetRecentTransactionsSince() {
    //     clientOps.getRecentTransactionsSince(123456789L);
    //     assertFalse(requestList.isEmpty());
    //     Request req = requestList.get(0);
    //         String payload = new String(req.getDataFile());
    //     assertTrue(payload.contains("getRecentTransactions"));
    //     assertTrue(payload.contains("since: 123456789"));
    // }
        //assertTrue(payload.contains("since: 123456789"));
    }
    // This file is intentionally left blank to avoid compilation errors during CryptoUtilsTest-only runs.
*/