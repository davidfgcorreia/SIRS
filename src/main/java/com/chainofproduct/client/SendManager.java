package com.chainofproduct.client;

import com.chainofproduct.utils.ApiCalls;
import com.chainofproduct.utils.Request;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class SendManager implements Runnable {
    private final BlockingQueue<Request> sendQueue;
    private final Object sendLock;
    private volatile boolean running = true;

    public SendManager(BlockingQueue<Request> sendQueue, Object sendLock) {
        this.sendQueue = sendQueue;
        this.sendLock = sendLock;
    }

    public void stop() {
        running = false;
        synchronized (sendLock) {
            sendLock.notifyAll();
        }
    }

    @Override
    public void run() {
        while (running) {
            try {
                final Request req;
                synchronized (sendLock) {
                    while (sendQueue.isEmpty() && running) {
                        sendLock.wait();
                    }
                    if (!running) break;
                    req = sendQueue.poll();
                }
                if (req != null) {
                    Runnable sendTask = () -> {
                        try {
                            if (req.getType() == 1 || req.getType() == 2) {
                                ApiCalls.actAsSender(
                                    req.getHost(),
                                    req.getPort(),
                                    req.getPrivKeyFile(),
                                    req.getPubKeyFile(),
                                    req.getReceiverPubKeyFile(),
                                    req.getDataFile()
                                );
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    };
                    new Thread(sendTask).start();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
