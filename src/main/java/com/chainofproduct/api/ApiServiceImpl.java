package com.chainofproduct.api;

import com.chainofproduct.grpc.ApiServiceProto;
import com.chainofproduct.grpc.ApiServiceGrpc;
import io.grpc.stub.StreamObserver;
import java.util.concurrent.BlockingQueue;

public class ApiServiceImpl extends ApiServiceGrpc.ApiServiceImplBase {
    private final BlockingQueue<Request> sendQueue;
    private final Object sendLock;

    public ApiServiceImpl(BlockingQueue<Request> sendQueue, Object sendLock) {
        this.sendQueue = sendQueue;
        this.sendLock = sendLock;
    }

    @Override
    public void sendTransaction(ApiServiceProto.TransactionRequest request, StreamObserver<ApiServiceProto.ApiReply> responseObserver) {
        try {
            // Parse gRPC request to new Request class, type=1 for transaction
            Request req = new Request(
                request.getHost(),
                request.getPort(),
                request.getPrivKeyFile(),
                request.getReceiverPubKeyFile(),
                request.getDataFile(),
                1
            );
            sendQueue.put(req);
            synchronized (sendLock) {
                sendLock.notifyAll();
            }
            ApiServiceProto.ApiReply reply = ApiServiceProto.ApiReply.newBuilder().setAck(true).build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(e);
        }
    }

    //era possivel so termos um service de grpc com mais um atributo do tipo de pedido mas n me apaeteceu fazer assim depois logo se ve

    @Override
    public void sendShare(ApiServiceProto.ShareRequest request, StreamObserver<ApiServiceProto.ApiReply> responseObserver) {
        try {
            // Parse gRPC request to new Request class, type=2 for share
            Request req = new Request(
                request.getHost(),
                request.getPort(),
                request.getPrivKeyFile(),
                request.getReceiverPubKeyFile(),
                request.getDataFile(),
                2
            );
            sendQueue.put(req);
            synchronized (sendLock) {
                sendLock.notifyAll();
            }
            ApiServiceProto.ApiReply reply = ApiServiceProto.ApiReply.newBuilder().setAck(true).build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(e);
        }
    }

    // The receive operations are not implemented here, as per your requirements.
}
