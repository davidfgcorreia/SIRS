package com.chainofproduct.client;

import com.chainofproduct.utils.ApiCalls;
import com.chainofproduct.utils.Request;

import java.util.concurrent.BlockingQueue;

public class SendManager implements Runnable {
    private final BlockingQueue<Request> sendQueue;
    private final Object sendLock;
    private volatile boolean running = true;
    private final ClientResponseHandler responseHandler;
    private Thread sendManagerThread;

    public SendManager(BlockingQueue<Request> sendQueue, Object sendLock) {
        this.sendQueue = sendQueue;
        this.sendLock = sendLock;
        this.responseHandler = new ClientResponseHandler();
    }

    public void start() {
        sendManagerThread = new Thread(() -> this.run(), "SendManager");
        sendManagerThread.setDaemon(true);
        sendManagerThread.start();
    }

    public void stop() {
        running = false;
        synchronized (sendLock) {
            sendLock.notifyAll();
        }
        if (sendManagerThread != null) {
            sendManagerThread.interrupt();
        }
    }

    public void join(long timeout) throws InterruptedException {
        if (sendManagerThread != null) {
            sendManagerThread.join(timeout);
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
                        byte[] result = null;
                        try {
                            result = ApiCalls.actAsSender(
                                req.getHost(),
                                req.getPort(),
                                req.getEntityType(),
                                req.getClientNum(),
                                req.getReceiverEntity(),
                                req.getDataFile()
                            );
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        if (result!= null){
                           responseHandler.handleResponse(result);
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
