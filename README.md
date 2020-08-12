# AnySync Self-hosted Server

An open source self-hosted cloud [server](https://anysync.net), a secure cloud storage service with end-to-end encryption.

## Features
- End-to-end file encryption: data is encrypted using 256-bit AES-GCM, and it can only be accessed with your key. Neither an administrator nor third parties can read the data.
- Incremental backup and sync.
- Smart sync (placeholder files): it helps you reduce local disk storage.
- Deduplication: only uniqure data is compressed and uploaded to the cloud.
- Versioned file backup and sync.

## Installation (32-bit Raspberry Pi OS &amp; 64-bit Linux)

- Download the [zip file](https://github.com/anysync/server/releases)
- Unzip it
- Run $INSTALL_DIR/bin/run.sh
  The first time it runs, it will create "~/.AnySync" directory and configure it.

- Run $INSTALL_DIR/bin/run.sh again to start the server.
  If you have firewall, you need to configure it to open port 65064 (for [MINIO](https://github.com/minio/) server) and 65065 (for AnySync server). The
  self-hosted edition uses MINIO server to store files as objects.

- You can add startup script (run.sh) to /etc/rc.local to start the server automatically after OS reboot.

Here is a sample rc.local on Raspberry Pi:
```
#!/bin/sh -e

#must be before 'exit 0'
su pi -c /home/pi/anysync/bin/run.sh

exit 0

```

Do not forget to make /etc/rc.local executable.

## Installation (64-bit Windows)

- Download the [Windows installer file](https://github.com/anysync/server/releases)
- Run the installer. After installation two Windows services will be installed. 
  If you have firewall, you need to configure it to open port 65064 (for [MINIO](https://github.com/minio/) server) and 65065 (for AnySync server). The
  self-hosted edition uses MINIO server to store files as objects. MINIO stores data on "%PROGRAMDATA%\AnySync\objects" directory.

## Technical Details
- Secure random 256-bit file key and auth key are generated.
- A [NaCl](https://en.wikipedia.org/wiki/NaCl_(software)) box public/private key pair is generated.
- In the login request, client sends out a data structure with these data:
-- Client version number.
-- Email as user name.
-- Newly generated box public key used by the server for encrypting access token.
- In the login response, it contains following data
-- User ID
-- Device ID
-- Access token encrypted by the box public key. Local box private key is used to decrypt it. The access token will be used on the client side for authentication.

[scrypt](https://en.wikipedia.org/wiki/Scrypt "scrypt") is used for generating key from user's password. Default scrypt parameters are 

`Params{N: 16384, R: 8, P: 1, SaltLen: 16, DKLen: 32}`

The key is used for encrypting the file key, auth key, access token and public/private key pair, and the encrypted data is saved to a local file called "master.keys", which will be sent to the server. In the future, user can use the password to decrypt the file and know all the keys so that all the user's cloud files can be decrypted.

The access token is saved to a local file called "access.keys", which is unecrypted. This file is for authenticating the user, similar to the private key file used by SSH client for passwordless login.

All files will be encrypted by the key using 256-bit [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode "AES-GCM"), then encrypted file will be uploaded to the cloud.

