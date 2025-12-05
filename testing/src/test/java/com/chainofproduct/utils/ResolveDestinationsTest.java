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
    }
}