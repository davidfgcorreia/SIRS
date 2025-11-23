package com.chainofproduct.client;

import com.chainofproduct.grpc.ServerServiceGrpc;
import com.chainofproduct.grpc.ServerServiceProto;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.util.Scanner;

public class ClientMain {
    public static void main(String[] args) {
        String target = "localhost:50051"; // Adjust as needed
        GrpcClient grpcClient = new GrpcClient(target);
        ClientOperations operations = new ClientOperations(grpcClient.getStub());
        CommandLine cli = new CommandLine(operations);
        cli.run();
        grpcClient.shutdown();
    }
}
