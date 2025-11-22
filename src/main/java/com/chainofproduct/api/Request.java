package com.chainofproduct.api;

public class Request {
    private final String host;
    private final int port;
    private final String privKeyFile;
    private final String receiverPubKeyFile;
    private final String dataFile;
    private final int requestType;

    public Request(String host, int port, String privKeyFile, String receiverPubKeyFile, String dataFile, int requestType) {
        this.host = host;
        this.port = port;
        this.privKeyFile = privKeyFile;
        this.receiverPubKeyFile = receiverPubKeyFile;
        this.dataFile = dataFile;
        this.requestType = requestType;
    }

    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getPrivKeyFile() { return privKeyFile; }
    public String getReceiverPubKeyFile() { return receiverPubKeyFile; }
    public String getDataFile() { return dataFile; }
    public int getType() { return requestType; }
}
