package com.chainofproduct.client;

import com.chainofproduct.grpc.ServerServiceProto;

public class ClientOperations {
    private final com.chainofproduct.grpc.ServerServiceGrpc.ServerServiceBlockingStub stub;

    public ClientOperations(com.chainofproduct.grpc.ServerServiceGrpc.ServerServiceBlockingStub stub) {
        this.stub = stub;
    }

    public void send(String dataFile, String destination) {
        ServerServiceProto.SendTransactionRequest sendReq = ServerServiceProto.SendTransactionRequest.newBuilder()
                .setDataFile(dataFile)
                .setDestination(destination)
                .build();
        ServerServiceProto.SendTransactionReply sendResp = stub.requestSend(sendReq);
        System.out.println("Send: " + sendResp.getMessage());
    }

    public void getById(long id) {
        ServerServiceProto.GetTransactionByIdRequest getByIdReq = ServerServiceProto.GetTransactionByIdRequest.newBuilder()
                .setTransactionId(id)
                .build();
        ServerServiceProto.TransactionRecord rec = stub.getTransactionById(getByIdReq);
        System.out.println("Transaction: " + rec);
    }

    public void getAll() {
        ServerServiceProto.GetAllTransactionsRequest getAllReq = ServerServiceProto.GetAllTransactionsRequest.newBuilder().build();
        ServerServiceProto.GetAllTransactionsReply allResp = stub.getAllTransactions(getAllReq);
        for (ServerServiceProto.TransactionRecord r : allResp.getTransactionsList()) {
            System.out.println(r);
        }
    }

    public void getShares(long tid) {
        ServerServiceProto.GetSharesRequest getSharesReq = ServerServiceProto.GetSharesRequest.newBuilder()
                .setTransactionId(tid)
                .build();
        ServerServiceProto.GetSharesReply sharesResp = stub.getShares(getSharesReq);
        System.out.println("Shares: " + sharesResp.getSharesList());
    }

    public void getSharesBy(long tid, String sharedBy) {
        ServerServiceProto.GetSharesBySharedByRequest getSharesByReq = ServerServiceProto.GetSharesBySharedByRequest.newBuilder()
                .setTransactionId(tid)
                .setSharedBy(sharedBy)
                .build();
        ServerServiceProto.GetSharesReply sharesByResp = stub.getSharesBySharedBy(getSharesByReq);
        System.out.println("Shares by '" + sharedBy + "': " + sharesByResp.getSharesList());
    }
}
