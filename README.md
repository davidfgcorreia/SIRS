# CryptoUtils CLI

This project provides a command-line interface (CLI) for cryptographic file protection, integrity, and authenticity using AES and HMAC. You can generate keys, protect files, check their safety, and unprotect (decrypt) them interactively.

## Prerequisites
- Java 11 or higher
- Maven

## Build the Project

From the project root directory, run:

```
mvn compile
```

## Run the Interactive CLI

From the project root directory, run:

```
mvn compile exec:java -Dexec.mainClass="com.chainofproduct.CryptoUtils"
```

You will see a prompt:

```
Cyprto-utilities interactive CLI. Type 'help' for commands, 'exit' to quit.
> 
```

## Available Commands

- `help`
  - Show all available commands and usage.
- `generateAESKey <output-file>`
  - Generates a random AES key (256 bits) and saves it to `keys/<output-file>` (base64-encoded).
- `generateHMACKey <output-file>`
  - Generates a random HMAC key (256 bits) and saves it to `keys/<output-file>` (base64-encoded).
- `protect <input-file> <aes-key-file> <hmac-key-file> <output-file>`
  - Encrypts and protects the input file using the provided AES and HMAC keys (read from files), writing the result to the output file.
- `check <input-file> <aes-key-file> <hmac-key-file>`
  - Verifies the integrity, authenticity, and freshness of the protected file using the provided keys (read from files).
- `unprotect <input-file> <aes-key-file> <hmac-key-file> <output-file>`
  - Decrypts and verifies the protected file, writing the original data to the output file.
- `exit`
  - Exit the CLI.

## Example Usage

1. **Generate Keys:**
   ```
   > generateAESKey myaes.key
   > generateHMACKey myhmac.key
   ```
   Keys will be saved in the `keys/` directory.

2. **Protect a File:**
   ```
   > protect inputs/transaction.json keys/myaes.key keys/myhmac.key outputs/transaction_received.json
   ```

3. **Check a File:**
   ```
   > check outputs/transaction_received.json keys/myaes.key keys/myhmac.key
   ```

4. **Unprotect a File:**
   ```
   > unprotect outputs/transaction_received.json keys/myaes.key keys/myhmac.key outputs/original.json
   ```

5. **Exit:**
   ```
   > exit
   ```

## Notes
- All keys must be base64-encoded (the CLI does this automatically).
- For `check` and `unprotect`, a 5-minute freshness window is enforced.
- All file paths are relative to the project root unless absolute paths are provided.

---

For any issues, please contact the project maintainer.
