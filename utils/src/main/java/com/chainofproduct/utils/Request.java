package com.chainofproduct.utils;

public class Request {
    private final String host;
    private final int port;
    private final String privKeyFile;
    private final String pubKeyFile;
    private final String receiverPubKeyFile;
    private final byte[] dataFile;

    public Request(String host, int port, String privKeyFile, String pubKeyFile, String receiverPubKeyFile, byte[] dataFile) {
        this.host = host;
        this.port = port;
        this.privKeyFile = privKeyFile;
        this.pubKeyFile = pubKeyFile;
        this.receiverPubKeyFile = receiverPubKeyFile;
        this.dataFile = dataFile;

    }

    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getPrivKeyFile() { return privKeyFile; }
    public String getPubKeyFile() { return pubKeyFile; }
    public String getReceiverPubKeyFile() { return receiverPubKeyFile; }
    public byte[] getDataFile() { return dataFile; }
}
