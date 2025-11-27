package com.chainofproduct.client;

import com.chainofproduct.grpc.ServerServiceGrpc;
import com.chainofproduct.grpc.ServerServiceProto;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.util.Scanner;

public class ClientMain {
    public static void main(String[] args) {

        // Shared queue and lock for sending requests (TLS direct communication)
        java.util.concurrent.BlockingQueue<com.chainofproduct.utils.Request> sendQueue = new java.util.concurrent.LinkedBlockingQueue<>();
        Object sendLock = new Object();

        // Start the send manager thread for direct machine-to-machine communication
        SendManager sendManager = new SendManager(sendQueue, sendLock);
        Thread sendManagerThread = new Thread(sendManager);
        sendManagerThread.setDaemon(true);
        sendManagerThread.start();

        // Pass sendQueue/sendLock to CLI or operations if needed for direct send commands
        // (Extend CommandLine/ClientOperations as needed to enqueue direct send requests)

        CommandLine cli = new CommandLine(operations);
        cli.run();

        // Shutdown send manager and gRPC client
        sendManager.stop();
        try {
            sendManagerThread.join(1000);
        } catch (InterruptedException ignored) {}
        grpcClient.shutdown();
    }
}
