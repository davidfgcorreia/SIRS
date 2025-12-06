package com.chainofproduct.utils;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

public class ResolveDestinations {
    public static class DestinationInfo {
        public final String ip;
        public final int port;
        public final int certPort;
        public final int signaturePort;
        public DestinationInfo(String ip, int port, int certPort, int signaturePort) {
            this.ip = ip;
            this.port = port;
            this.certPort = certPort;
            this.signaturePort = signaturePort;
        }
    }

    // Simple resolve: expects exact formatting, no error handling for variations
    public static DestinationInfo resolve(String destinationName) {
        return resolve(destinationName, "localization_info/elemets_info.json");
    }

    // New overloaded method that accepts the JSON file path
    public static DestinationInfo resolve(String destinationName, String jsonPath) {
        try {
            String json = new String(Files.readAllBytes(Paths.get(jsonPath)), StandardCharsets.UTF_8);
            String entryKey = destinationName;
            int idx = json.indexOf(entryKey);
            if (idx == -1) return null;
            // Correctly extract the value for "ip"
            int ipKeyIdx = json.indexOf("\"ip\"", idx);
            int ipColonIdx = json.indexOf(':', ipKeyIdx);
            int ipQuoteStart = json.indexOf('"', ipColonIdx);
            int ipValueStart = ipQuoteStart + 1;
            int ipValueEnd = json.indexOf('"', ipValueStart);
            String ip = json.substring(ipValueStart, ipValueEnd);
            int portIdx = json.indexOf(':', json.indexOf("port", idx)) + 1;
            int portEnd = json.indexOf(',', portIdx);
            if (portEnd == -1) portEnd = json.indexOf('}', portIdx);
            String portStr = json.substring(portIdx, portEnd).trim();
            int port = Integer.parseInt(portStr);
            // Try to extract certPort if present
            int certPort = -1;
            int certPortIdx = json.indexOf("certPort", idx);
            if (certPortIdx != -1) {
                int certPortColon = json.indexOf(':', certPortIdx) + 1;
                int certPortEnd = json.indexOf(',', certPortColon);
                if (certPortEnd == -1) certPortEnd = json.indexOf('}', certPortColon);
                String certPortStr = json.substring(certPortColon, certPortEnd).trim();
                try {
                    certPort = Integer.parseInt(certPortStr);
                } catch (Exception ignore) {
                    certPort = port + 1000; // fallback
                }
            } else {
                certPort = port + 1000; // fallback if not present
            }
            // Try to extract signaturePort if present
            int signaturePort = -1;
            int signaturePortIdx = json.indexOf("signaturePort", idx);
            if (signaturePortIdx != -1) {
                int signaturePortColon = json.indexOf(':', signaturePortIdx) + 1;
                int signaturePortEnd = json.indexOf(',', signaturePortColon);
                if (signaturePortEnd == -1) signaturePortEnd = json.indexOf('}', signaturePortColon);
                String signaturePortStr = json.substring(signaturePortColon, signaturePortEnd).trim();
                try {
                    signaturePort = Integer.parseInt(signaturePortStr);
                } catch (Exception ignore) {
                    signaturePort = port + 2000; // fallback
                }
            } else {
                signaturePort = port + 2000; // fallback if not present
            }
            return new DestinationInfo(ip, port, certPort, signaturePort);
        } catch (Exception e) {
            return null;
        }
    }
}
