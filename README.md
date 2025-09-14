# admind
The remote flashing and management API endpoint.

## Setting a hashed password

To set a hashed password, /data/passwd.argon2id needs to be created and written
with the PHC string. The file MUST NOT contain a trailing CR or LF. Assuming
the writable rustkrazy partition is mounted at /data, you can use the following
command to populate the file using a random salt:

```
argon2 $(head -c 16 /dev/urandom | base64) -id -t 2 -k 19456 -p 1 -l 32 -e | tr -d '\n' > /data/passwd.argon2id
```

The time cost is 2, the memory cost is 19456 KiB, the parallelism is 1 and the
output length is 32.
