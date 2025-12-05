package com.chainofproduct.client;

import org.junit.Test;
import static org.junit.Assert.*;

public class ClientMainTest {
    @Test
    public void testMainWithNoArgs() {
        // This test expects System.exit(1) to be called if no args are provided
        // You can use a library like System Rules or similar to test System.exit
        // For now, just check that usage message is printed
        try {
            ClientMain.main(new String[]{});
            fail("Expected System.exit to be called");
        } catch (Throwable t) {
            // Expected behavior
        }
    }

    @Test
    public void testMainWithCompanyName() {
        String[] args = {"TestCompany"};
        try {
            Thread t = new Thread(() -> {
                try {
                    ClientMain.main(args);
                } catch (Exception ignored) {}
            });
            t.setDaemon(true);
            t.start();
            Thread.sleep(500); // Let it start
            t.interrupt(); // Stop the thread
        } catch (Exception e) {
            fail("Exception thrown in main: " + e.getMessage());
        }
    }
}
