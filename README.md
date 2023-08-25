
# SQLCipherED

Standalone SQLCipher database decryptor

[SQLCipher major revisions (1,2,3,4)](https://utelle.github.io/SQLite3MultipleCiphers/docs/ciphers/cipher_sqlcipher/)

[SQLCipher design info](https://www.zetetic.net/sqlcipher/design/)

[SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/)

## Usage

```
runner-sqlcipher-ed -i [dbSource] [-p [passphrase] or -b [hexString]] {-o [outputPath] -v [sqlCipherVersion] -ps [pageSize] -ka [keyKdfAlgo] -ki [keyKdfIter] -ha [hmacKdfAlgo] }
```

| Key | Parameter name        | Required | Description                                                           | Default value  |
|-----|-----------------------|----------|-----------------------------------------------------------------------|----------------|
| -i  | Database source       |   **+**  | SQLCipher source path                                                 |                |
| -p  | Passphrase            |   **+**  | SQLCipher key derivation passphrase                                   |                |
| -b  | Cipher key hex string |   **+**  | SQLCipher cipher key (32 bytes in 64 hex-chars). Overrides passphrase |                |
| -o  | Output path           |          | Output file path                                                      | {input}.sqlite |
| -v  | DB cipher version     |          | SQLCipher major revision version number (1,2,3 or 4)                  |       4        |
| -ps | DB page size          |          | DB page size in bytes (pow of two from 512 to 65536). Overrides default value of standard version |                |
| -ka | PBKDF2 algo           |          | Key derivation algo (SHA1, SHA256, SHA512). Overrides default value of standard version           |                |
| -ki | PBKDF2 iterations     |          | Key derivation iterations count. Overrides default value of standard version                      |                |
| -ha | HMAC algo             |          | Page signature algo (SHA1, SHA256, SHA512). Overrides default value of standard version           |                |
| -h  | Show help             |          | Show help                                                             |                |