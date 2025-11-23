package com.chainofproduct.server;

import com.chainofproduct.grpc.ServerServiceProto;
import com.chainofproduct.grpc.ServerServiceGrpc;
import io.grpc.stub.StreamObserver;
import java.util.concurrent.BlockingQueue;
import com.chainofproduct.db.DatabaseOperations;

public class ServerServiceImpl extends ServerServiceGrpc.ServerServiceImplBase {

    private final ServerOperations serverOperations;

    public ServerServiceImpl(BlockingQueue<Request> sendQueue, Object sendLock) {
        this.serverOperations = new ServerOperations(sendQueue, sendLock);
    }

    // Implements: rpc RequestSend (SendTransactionRequest) returns (SendTransactionReply);
    @Override
    public void requestSend(ServerServiceProto.SendTransactionRequest request, StreamObserver<ServerServiceProto.SendTransactionReply> responseObserver) {
        try {
            // Delegate to ServerOperations to resolve destination, prepare args, queue request, and handle DB logic
            boolean ok = serverOperations.handleSendTransaction(request.getDataFile(), request.getDestination());
            ServerServiceProto.SendTransactionReply reply = ServerServiceProto.SendTransactionReply.newBuilder()
                .setSuccess(ok)
                .setMessage(ok ? "Transaction request processed." : "Failed to process transaction request.")
                .build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        } catch (Exception e) {
            ServerServiceProto.SendTransactionReply reply = ServerServiceProto.SendTransactionReply.newBuilder()
                .setSuccess(false)
                .setMessage("Error: " + e.getMessage())
                .build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }
    }

    // Implements: rpc GetTransactionById (GetTransactionByIdRequest) returns (TransactionRecord);
    @Override
    public void getTransactionById(ServerServiceProto.GetTransactionByIdRequest request, StreamObserver<ServerServiceProto.TransactionRecord> responseObserver) {
        try {
            DatabaseOperations.TransactionRecord rec = DatabaseOperations.getTransactionById(request.getTransactionId());
            if (rec != null) {
                ServerServiceProto.TransactionRecord protoRec = ServerServiceProto.TransactionRecord.newBuilder()
                    .setId(rec.id)
                    .setTimestamp(rec.timestamp)
                    .setSeller(rec.seller)
                    .setBuyer(rec.buyer)
                    .setProduct(rec.product)
                    .setUnits(rec.units)
                    .setAmount(rec.amount)
                    .build();
                responseObserver.onNext(protoRec);
            }
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(e);
        }
    }

    // Implements: rpc GetAllTransactions (GetAllTransactionsRequest) returns (GetAllTransactionsReply);
    @Override
    public void getAllTransactions(ServerServiceProto.GetAllTransactionsRequest request, StreamObserver<ServerServiceProto.GetAllTransactionsReply> responseObserver) {
        try {
            java.util.List<DatabaseOperations.TransactionRecord> recs = DatabaseOperations.getAllTransactions();
            ServerServiceProto.GetAllTransactionsReply.Builder reply = ServerServiceProto.GetAllTransactionsReply.newBuilder();
            for (DatabaseOperations.TransactionRecord rec : recs) {
                reply.addTransactions(ServerServiceProto.TransactionRecord.newBuilder()
                    .setId(rec.id)
                    .setTimestamp(rec.timestamp)
                    .setSeller(rec.seller)
                    .setBuyer(rec.buyer)
                    .setProduct(rec.product)
                    .setUnits(rec.units)
                    .setAmount(rec.amount)
                    .build());
            }
            responseObserver.onNext(reply.build());
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(e);
        }
    }

    // Implements: rpc GetShares (GetSharesRequest) returns (GetSharesReply);
    @Override
    public void getShares(ServerServiceProto.GetSharesRequest request, StreamObserver<ServerServiceProto.GetSharesReply> responseObserver) {
        try {
            java.util.List<String> shares = DatabaseOperations.getShares(request.getTransactionId());
            ServerServiceProto.GetSharesReply reply = ServerServiceProto.GetSharesReply.newBuilder()
                .addAllShares(shares)
                .build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(e);
        }
    }

    // Implements: rpc GetSharesBySharedBy (GetSharesBySharedByRequest) returns (GetSharesReply);
    @Override
    public void getSharesBySharedBy(ServerServiceProto.GetSharesBySharedByRequest request, StreamObserver<ServerServiceProto.GetSharesReply> responseObserver) {
        try {
            java.util.List<String> shares = DatabaseOperations.getSharesBySharedBy(request.getTransactionId(), request.getSharedBy());
            ServerServiceProto.GetSharesReply reply = ServerServiceProto.GetSharesReply.newBuilder()
                .addAllShares(shares)
                .build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(e);
        }
    }
}
