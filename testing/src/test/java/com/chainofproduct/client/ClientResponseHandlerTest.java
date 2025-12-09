package com.chainofproduct.client;

import org.junit.*;
import static org.junit.Assert.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ClientResponseHandlerTest {
    private ClientResponseHandler handler;
    private Path outputsDir;

    @Before
    public void setUp() throws Exception {
        handler = new ClientResponseHandler();
        outputsDir = Paths.get("outputs");
        if (Files.exists(outputsDir)) {
            Files.walk(outputsDir)
                .map(Path::toFile)
                .sorted((a, b) -> -a.compareTo(b))
                .forEach(f -> f.delete());
        }
        Files.createDirectories(outputsDir);
    }

    @After
    public void tearDown() throws Exception {
        if (Files.exists(outputsDir)) {
            Files.walk(outputsDir)
                .map(Path::toFile)
                .sorted((a, b) -> -a.compareTo(b))
                .forEach(f -> f.delete());
        }
    }

    @Test
    public void testHandleGetByIdResponse() throws Exception {
        String header = "{\"request_type\":\"getById\",\"files\":1,\"filename\":\"testfile\"}";
        byte[] json = "{\"seller\":\"A\",\"buyer\":\"B\"}".getBytes(StandardCharsets.UTF_8);
        byte[] sig = new byte[344];
        Arrays.fill(sig, (byte)'A');
        byte[] sig2 = new byte[344];
        Arrays.fill(sig2, (byte)'B');
        byte[] file = new byte[json.length + sig.length + sig2.length];
        System.arraycopy(json, 0, file, 0, json.length);
        System.arraycopy(sig, 0, file, json.length, sig.length);
        System.arraycopy(sig2, 0, file, json.length + sig.length, sig2.length);
        byte[] headerBytes = header.getBytes(StandardCharsets.UTF_8);
        byte[] marker = "file1:".getBytes(StandardCharsets.UTF_8);
        byte[] response = new byte[headerBytes.length + marker.length + file.length];
        System.arraycopy(headerBytes, 0, response, 0, headerBytes.length);
        System.arraycopy(marker, 0, response, headerBytes.length, marker.length);
        System.arraycopy(file, 0, response, headerBytes.length + marker.length, file.length);
        handler.handleResponse(response);
        Path jsonOut = outputsDir.resolve("testfile.json");
        Path binOut = outputsDir.resolve("testfile_withsigs.bin");
        assertTrue(Files.exists(jsonOut));
        assertTrue(Files.exists(binOut));
        byte[] jsonOutBytes = Files.readAllBytes(jsonOut);
        assertTrue(new String(jsonOutBytes, StandardCharsets.UTF_8).contains("seller"));
        byte[] binOutBytes = Files.readAllBytes(binOut);
        assertEquals(file.length, binOutBytes.length);
    }

    @Test
    public void testHandleGetAllResponse() throws Exception {
        String header = "{\"request_type\":\"getAll\",\"files\":2}";
        String[] names = {"test1", "test2"};
        byte[] json = "{\"seller\":\"A\",\"buyer\":\"B\"}".getBytes(StandardCharsets.UTF_8);
        byte[] sig = new byte[344];
        Arrays.fill(sig, (byte)'A');
        byte[] sig2 = new byte[344];
        Arrays.fill(sig2, (byte)'B');
        byte[] file = new byte[json.length + sig.length + sig2.length];
        System.arraycopy(json, 0, file, 0, json.length);
        System.arraycopy(sig, 0, file, json.length, sig.length);
        System.arraycopy(sig2, 0, file, json.length + sig.length, sig2.length);
        byte[] headerBytes = header.getBytes(StandardCharsets.UTF_8);
        byte[][] sections = new byte[names.length][];
        int totalLen = headerBytes.length;
        for (int i = 0; i < names.length; i++) {
            byte[] marker = ("file" + (i+1) + ":" + names[i] + ":").getBytes(StandardCharsets.UTF_8);
            sections[i] = new byte[marker.length + file.length];
            System.arraycopy(marker, 0, sections[i], 0, marker.length);
            System.arraycopy(file, 0, sections[i], marker.length, file.length);
            totalLen += sections[i].length;
        }
        byte[] response = new byte[totalLen];
        System.arraycopy(headerBytes, 0, response, 0, headerBytes.length);
        int cursor = headerBytes.length;
        for (int i = 0; i < names.length; i++) {
            System.arraycopy(sections[i], 0, response, cursor, sections[i].length);
            cursor += sections[i].length;
        }
        handler.handleResponse(response);
        for (String name : names) {
            Path jsonOut = outputsDir.resolve(name + ".json");
            Path binOut = outputsDir.resolve(name + "_withsigs.bin");
            assertTrue("Missing output file: " + jsonOut, Files.exists(jsonOut));
            assertTrue("Missing output file: " + binOut, Files.exists(binOut));
            byte[] jsonOutBytes = Files.readAllBytes(jsonOut);
            assertTrue(new String(jsonOutBytes, StandardCharsets.UTF_8).contains("seller"));
            byte[] binOutBytes = Files.readAllBytes(binOut);
            assertEquals(file.length, binOutBytes.length);
        }
    }

    @Test
    public void testHandleGetSharesResponse() throws Exception {
        String header = "{\"request_type\":\"getShares\",\"files\":0}";
        String json = "{\"shares\":[{\"seller\":\"A\",\"buyer\":\"B\"}]}";
        byte[] response = (header + json).getBytes(StandardCharsets.UTF_8);
        handler.handleResponse(response);
        // No file output, just check for no exception
    }

    @Test
    public void testHandleGetSharesByResponse() throws Exception {
        String header = "{\"request_type\":\"getSharesBy\",\"files\":0}";
        String json = "{\"shares\":[{\"seller\":\"A\",\"buyer\":\"B\"}]}";
        byte[] response = (header + json).getBytes(StandardCharsets.UTF_8);
        handler.handleResponse(response);
        // No file output, just check for no exception
    }

    @Test
    public void testHandleMalformedResponse() throws Exception {
        byte[] response = "nojsonhere".getBytes(StandardCharsets.UTF_8);
        handler.handleResponse(response);
        // Should print error, no exception
    }
}
