# ChainOfProduct — Cryptographic File Protection

SIRS 2025/2026 coursework with client, server, database, and shared cryptographic utilities. The `CryptoUtils` command line protects files using **AES-GCM**, authenticates their contents, and checks freshness/replay information.

## Modules

- `utils`: cryptographic operations, key transmission, and certificates.
- `client`: client entry point.
- `server`: service entry point.
- `db`: database service.
- `testing`: separate integration/test sources.

## Build

Requires Java 17 and Maven:

```sh
mvn clean install
```

## CryptoUtils CLI

From the `utils/` directory:

```sh
mvn compile exec:java -Dexec.mainClass=com.chainofproduct.utils.CryptoUtils
```

Enter commands inside the CLI:

```text
help
generateAESKey demo.key
protect input.txt keys/demo.key protected.bin
check protected.bin keys/demo.key
unprotect protected.bin keys/demo.key recovered.txt
exit
```

Use your own local sample file and generated key. Keep keys, certificates containing private material, and real application data out of Git.

The checked source uses AES-GCM; `generateHMACKey` and `initHMACKeys` appear in its help text but are not handled by the current command switch. The older HMAC-oriented instructions are archived in [docs/LEGACY_README.md](docs/LEGACY_README.md) for context, not as current run instructions.
