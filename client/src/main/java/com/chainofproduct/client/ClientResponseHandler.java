package com.chainofproduct.client;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ClientResponseHandler {

    /**
     * Handle the response from the server, parse it, and take action based on the response content.
     * @param responseBytes The decrypted response bytes from the server
     */
    public void handleResponse(byte[] responseBytes) {
        // 1. Extract JSON header (up to first '}')
        int headerEnd = -1;
        for (int i = 0; i < responseBytes.length; i++) {
            if (responseBytes[i] == '}') {
                headerEnd = i;
                break;
            }
        }
        if (headerEnd == -1) {
            System.out.println("Malformed response: missing JSON header");
            return;
        }
        String headerJson = new String(responseBytes, 0, headerEnd + 1, StandardCharsets.UTF_8);
        String responseType = extractJsonStringField(headerJson, "request_type");
        int numFiles = extractJsonIntField(headerJson, "files");
        String filename = extractJsonStringField(headerJson, "filename");
        if (responseType == null) {
            System.out.println("Response: " + headerJson);
            return;
        }
        // 2. Parse file sections (if any)
        int cursor = headerEnd + 1;
        // Skip any whitespace/newlines after header
        while (cursor < responseBytes.length && (responseBytes[cursor] == '\n' || responseBytes[cursor] == '\r' || responseBytes[cursor] == ' ')) cursor++;

        switch (responseType) {
            case "getById": {
                // At most one file: file1: <json file + 2 signatures at end>
                if (numFiles < 1) {
                    System.out.println("No files in getById response");
                    return;
                }
                int[] file1Bounds = findFileSection(responseBytes, cursor, "file1:");
                if (file1Bounds == null) {
                    System.out.println("Malformed getById response: missing file1");
                    return;
                }
                byte[] file1 = new byte[file1Bounds[1] - file1Bounds[0]];
                System.arraycopy(responseBytes, file1Bounds[0], file1, 0, file1.length);
                int sigLen = 344;
                if (file1.length < sigLen * 2) {
                    System.err.println("ERROR: Malformed getById file: too short for two signatures. File not saved.");
                } else {
                    int contentLen = file1.length - sigLen * 2;
                    byte[] content = new byte[contentLen];
                    System.arraycopy(file1, 0, content, 0, contentLen);
                    saveToFile("outputs/" + filename + ".json", content);
                    saveToFile("outputs/" + filename + "_withsigs.bin", file1);
                    System.out.println("getById JSON file content:\n" + new String(content, StandardCharsets.UTF_8));
                    System.out.println("Full file with signatures saved as outputs/" + filename + "_withsigs.bin");
                }
                break;
            }
            case "getAll":
            case "getRecentTransactions": {
                // Each file section: fileX:filename:<json+signatures>
                if (numFiles < 1) {
                    System.out.println(responseType + ": No files in response");
                    break;
                }
                int sigLen = 344;
                for (int i = 1; i <= numFiles; i++) {
                    String marker = "file" + i + ":";
                    int[] bounds = findFileSection(responseBytes, cursor, marker);
                    if (bounds == null) break;
                    // Find the filename (up to the first colon)
                    int nameStart = bounds[0];
                    int nameEnd = nameStart;
                    while (nameEnd < bounds[1] && responseBytes[nameEnd] != ':') nameEnd++;
                    if (nameEnd >= bounds[1]) {
                        System.err.println("ERROR: Malformed file section: missing filename colon");
                        cursor = bounds[1];
                        continue;
                    }
                    String fileName = new String(responseBytes, nameStart, nameEnd - nameStart, StandardCharsets.UTF_8).replaceAll("[\r\n ]", "");
                    int dataStart = nameEnd + 1;
                    int dataLen = bounds[1] - dataStart;
                    if (dataLen < sigLen * 2) {
                        System.err.println("ERROR: Malformed " + responseType + " file '" + fileName + "': too short for two signatures. File not saved.");
                        cursor = bounds[1];
                        continue;
                    }
                    byte[] file = new byte[dataLen];
                    System.arraycopy(responseBytes, dataStart, file, 0, dataLen);
                    int contentLen = file.length - sigLen * 2;
                    byte[] content = new byte[contentLen];
                    System.arraycopy(file, 0, content, 0, contentLen);
                    saveToFile("outputs/" + fileName + ".json", content);
                    saveToFile("outputs/" + fileName + "_withsigs.bin", file);
                    System.out.println(responseType + " file '" + fileName + "' JSON content:\n" + new String(content, StandardCharsets.UTF_8));
                    System.out.println("Full file with signatures saved as outputs/" + fileName + "_withsigs.bin");
                    cursor = bounds[1];
                }
                break;
            }
            case "getShares":
            case "getSharesBy": {
                // Expecting: JSON with seller/buyer shares and names
                String jsonStr = new String(responseBytes, cursor, responseBytes.length - cursor, StandardCharsets.UTF_8).trim();
                // Simple pretty-print: try to indent braces and brackets
                String pretty = jsonStr.replaceAll("([\\{\\}\\[\\]])", "\n$1\n")
                                      .replaceAll(",", ",\n")
                                      .replaceAll("\n+", "\n");
                System.out.println(responseType + " result (parsed):\n" + pretty.trim());
                break;
            }
            default:
                System.out.println("Response: " + headerJson);
                break;
        }
    }

    // Helper: find the start and end of a file section marked by 'fileX:'
    private int[] findFileSection(byte[] data, int start, String marker) {
        String markerStr = marker;
        int markerIdx = indexOf(data, markerStr.getBytes(StandardCharsets.UTF_8), start);
        if (markerIdx == -1) return null;
        int fileStart = markerIdx + markerStr.length();
        // Find next file marker or end of data
        int nextMarker = -1;
        for (int i = fileStart; i < data.length - 5; i++) {
            if (data[i] == 'f' && data[i+1] == 'i' && data[i+2] == 'l' && data[i+3] == 'e' && Character.isDigit(data[i+4]) && data[i+5] == ':') {
                nextMarker = i;
                break;
            }
        }
        int fileEnd = (nextMarker == -1) ? data.length : nextMarker;
        // Trim leading whitespace
        while (fileStart < fileEnd && (data[fileStart] == '\n' || data[fileStart] == '\r' || data[fileStart] == ' ')) fileStart++;
        // Trim trailing whitespace
        while (fileEnd > fileStart && (data[fileEnd-1] == '\n' || data[fileEnd-1] == '\r' || data[fileEnd-1] == ' ')) fileEnd--;
        return new int[] {fileStart, fileEnd};
    }

    // Helper: find the index of a byte pattern in a byte array
    private int indexOf(byte[] data, byte[] pattern, int start) {
        outer: for (int i = start; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) continue outer;
            }
            return i;
        }
        return -1;
    }


    private void saveToFile(String filePath, byte[] data) {
        try {
            Files.createDirectories(Paths.get(filePath).getParent());
            Files.write(Paths.get(filePath), data);
        } catch (Exception e) {
            System.err.println("Failed to save response to file: " + e.getMessage());
        }
    }

    // Helper to extract a string field from a JSON object (with double quotes)
    private String extractJsonStringField(String json, String field) {
        String key = "\"" + field + "\":";
        int idx = json.indexOf(key);
        if (idx == -1) return null;
        int start = json.indexOf('"', idx + key.length());
        int end = json.indexOf('"', start + 1);
        if (start == -1 || end == -1) return null;
        return json.substring(start + 1, end);
    }

    // Helper to extract an integer field from a JSON object (with double quotes)
    private int extractJsonIntField(String json, String field) {
        String key = "\"" + field + "\":";
        int idx = json.indexOf(key);
        if (idx == -1) return 0;
        int start = idx + key.length();
        // Skip whitespace
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) end++;
        if (start == end) return 0;
        try {
            return Integer.parseInt(json.substring(start, end));
        } catch (Exception e) {
            return 0;
        }
    }
    }
