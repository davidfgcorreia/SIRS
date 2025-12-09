package com.chainofproduct.utils;

import org.junit.Test;
import static org.junit.Assert.*;

public class ResolveDestinationsTest {
    @Test
    public void testResolveDestination() {
        // This assumes localization_info/elemets_info.json exists and is properly formatted
        ResolveDestinations.DestinationInfo info = ResolveDestinations.resolve("TestCompany", "../localization_info/elemets_info.json");
        assertNotNull("DestinationInfo should not be null", info);
        assertEquals("IP should be localhost", "localhost", info.ip);
        assertEquals("Port should be 5001", 5001, info.port);
        // If certPort is present in the JSON, check its value; otherwise, check the default
        int expectedCertPort = 6001; // If your JSON has certPort, set this accordingly; else, port+1000
        assertEquals("certPort should be 6001 (or port+1000)", expectedCertPort, info.certPort);
        int expectedSignaturePort = 7001; // If your JSON has signaturePort, set this accordingly; else, port+2000
        assertEquals("signaturePort should be 7001 (or port+2000)", expectedSignaturePort, info.signaturePort);
    }

    @Test
    public void testResolveGroupNames() {
        java.util.List<String> names = ResolveDestinations.resolve("groupCClients", true, "../localization_info/elemets_info.json");
        assertNotNull("Group names list should not be null", names);
        assertEquals("Group should have 3 members", 3, names.size());
        assertTrue("Group should contain clientA", names.contains("clientA"));
        assertTrue("Group should contain clientB", names.contains("clientB"));
        assertTrue("Group should contain clientC", names.contains("clientC"));
    }
}