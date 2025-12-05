package com.chainofproduct.utils;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

public class ResolveDestinations {
    public static class DestinationInfo {
        public final String ip;
        public final int port;
        public DestinationInfo(String ip, int port) {
            this.ip = ip;
            this.port = port;
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
            return new DestinationInfo(ip, port);
        } catch (Exception e) {
            return null;
        }
    }
}
