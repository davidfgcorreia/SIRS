package com.chainofproduct.utils;

public class Request {
    private final String host;
    private final int port;
    private final String entityType;
    private final int clientNum;
    private final String receiverEntity;
    private final byte[] dataFile;

    public Request(String host, int port, String entityType, int clientNum, String receiverEntity, byte[] dataFile) {
        this.host = host;
        this.port = port;
        this.entityType = entityType;
        this.clientNum = clientNum;
        this.receiverEntity = receiverEntity;
        this.dataFile = dataFile;
    }

    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getEntityType() { return entityType; }
    public int getClientNum() { return clientNum; }
    public String getReceiverEntity() { return receiverEntity; }
    public byte[] getDataFile() { return dataFile; }
}
