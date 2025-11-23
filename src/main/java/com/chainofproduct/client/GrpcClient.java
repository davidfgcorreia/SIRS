package com.chainofproduct.client;

import com.chainofproduct.grpc.ServerServiceGrpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class GrpcClient {
    private final ManagedChannel channel;
    private final ServerServiceGrpc.ServerServiceBlockingStub stub;

    public GrpcClient(String target) {
        this.channel = ManagedChannelBuilder.forTarget(target)
                .usePlaintext()
                .build();
        this.stub = ServerServiceGrpc.newBlockingStub(channel);
    }

    public ServerServiceGrpc.ServerServiceBlockingStub getStub() {
        return stub;
    }

    public void shutdown() {
        channel.shutdown();
    }
}
