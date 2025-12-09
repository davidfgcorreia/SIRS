package com.chainofproduct.client;

import java.util.Scanner;

public class CommandLine {
    private final ClientOperations operations;

    public CommandLine(ClientOperations operations) {
        this.operations = operations;
    }

    public void run() {
        System.out.println("Client started. Type 'exit' to quit.");
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.print("> ");
                String line = scanner.nextLine();
                if (line == null || line.trim().equalsIgnoreCase("exit")) {
                    break;
                }
                String[] parts = line.trim().split("\\s+");
                if (parts.length == 0) continue;
                String cmd = parts[0].toLowerCase();
                try {
                    switch (cmd) {
                            case "groupupdate":
                                if (parts.length < 4) {
                                    System.out.println("Usage: groupupdate <group_name> <add1,add2,...> <remove1,remove2,...>");
                                    break;
                                }
                                String groupName = parts[1];
                                java.util.List<String> additions = java.util.Arrays.asList(parts[2].split(","));
                                java.util.List<String> removals = java.util.Arrays.asList(parts[3].split(","));
                                operations.updateGroup(groupName, additions, removals);
                                break;
                        case "send":
                            if (parts.length < 4) {
                                System.out.println("Usage: send <data_file> <destination> <group>");
                                break;
                            }
                            operations.sendtrsaction(parts[1], parts[2],Boolean.parseBoolean(parts[3]));
                            break;
                        case "getbyid":
                            if (parts.length < 2) {
                                System.out.println("Usage: getbyid <transaction_id>");
                                break;
                            }
                            operations.gettransactionById(Long.parseLong(parts[1]));
                            break;
                        case "getall":
                            operations.getAll();
                            break;
                        case "getshares":
                            if (parts.length < 2) {
                                System.out.println("Usage: getshares <transaction_id>");
                                break;
                            }
                            operations.getShares(Long.parseLong(parts[1]));
                            break;
                        case "getsharesby":
                            if (parts.length < 3) {
                                System.out.println("Usage: getsharesby <transaction_id> <shared_by>");
                                break;
                            }
                            operations.getSharesBy(Long.parseLong(parts[1]), parts[2]);
                            break;
                        case "getrecent":
                            if (parts.length < 2) {
                                System.out.println("Usage: getrecent <since_timestamp>");
                                break;
                            }
                            operations.getRecentTransactionsSince(Long.parseLong(parts[1]));
                            break;
                        case "verifyfile":
                            if (parts.length < 2) {
                                System.out.println("Usage: verifyfile <decrypted_file>");
                                break;
                            }
                            boolean valid = operations.verifyFileIntegrity(parts[1]);
                            System.out.println("File integrity: " + (valid ? "VALID" : "TAMPERED"));
                            break;
                        default:
                                System.out.println("Unknown command. Supported: send, getbyid, getall, getshares, getsharesby, getrecent, verifyfile, groupupdate, exit");
                    }
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
            }
        }
        System.out.println("Client exit.");
    }
}
