# AnySync Self-hosted Server

An open source self-hosted cloud [server](https://anysync.net), a secure cloud storage service with end-to-end encryption.

## Features
- End-to-end file encryption: data is encrypted using 256-bit AES-GCM, and it can only be accessed with your key. Neither an administrator nor third parties can read the data.
- Incremental backup and sync.
- Smart sync (placeholder files): it helps you reduce local disk storage.
- Deduplication: only uniqure data is compressed and uploaded to the cloud.
- Versioned file backup and sync.

## Installation (64-bit Linux)

- Download the [zip file](https://github.com/anysync/server/releases)
- Unzip it on a 64-bit Linux
- Run $INSTALL_DIR/bin/run.sh
  The first time it runs, it will create "~/.AnySync" directory and configure it.

- Run $INSTALL_DIR/bin/run.sh again to start the server.
  If you have firewall, you need to configure it to open port 65064 (for [MINIO](https://github.com/minio/) server) and 65065 (for AnySync server). The
  self-hosted edition uses MINIO server to store files as objects.

