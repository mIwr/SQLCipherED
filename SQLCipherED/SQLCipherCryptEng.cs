using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SQLCipherED
{
    /// <summary>
    /// Represents standalone SQLCipher database cryptographic provider
    /// </summary>
    public class SQLCipherCryptEng
    {
        /// <summary>
        /// Cipher key derivation iterations count
        /// </summary>
        public int KdfIter { get; private set; }
        /// <summary>
        /// Cipher key derivation algo
        /// </summary>
        public SQLCipherHashAlgo PbkdfAlgo { get; private set; }
        /// <summary>
        /// Page data HMAC key derivation algo
        /// </summary>
        public SQLCipherHashAlgo? HmacPbkdfAlgo { get; private set; }
        /// <summary>
        /// SQLCipher page size: encoded payload data and meta
        /// </summary>
        public ushort PageSize { get; private set; }
        /// <summary>
        /// HMAC key derivation iterations count
        /// </summary>
        public int HmacKdfIter { get; private set; }
        /// <summary>
        /// HMAC key derivation salt mask
        /// </summary>
        public byte HmacSaltMask { get; private set; }        
        /// <summary>
        /// HMAC digest size
        /// </summary>
        public byte HmacSize
        {
            get
            {
                return HmacPbkdfAlgo?.Size() ?? 0;
            }
        }

        /// <summary>
        /// Payload data size of the page
        /// </summary>
        public ushort PayloadPageSize
        {
            get
            {
                var size = PageSize;
                size -= ReservePageSize;
                return size;
            }
        }

        /// <summary>
        /// IV + HMAC (if exists) size at end of the page
        /// </summary>
        public byte ReservePageSize
        {
            get
            {
                switch (HmacPbkdfAlgo)
                {
                    case SQLCipherHashAlgo.SHA1: return 48;//(IV + HMAC SHA1 sz) => padding
                    case SQLCipherHashAlgo.SHA256: return 48;//IV + HMAC SHA256 sz
                    case SQLCipherHashAlgo.SHA512: return 80;//IV + HMAC SHA512 sz
                    default: return 16;
                }
            }
        }

        /// <summary>
        /// Creates new instance with standard params
        /// </summary>
        /// <param name="standard">SQLCipher database version</param>
        public SQLCipherCryptEng(SQLCipherStandard standard)
        {
            KdfIter = standard.KdfIter();
            PbkdfAlgo = standard.PbkdfAlgo();
            PageSize = standard.PageSize();
            HmacPbkdfAlgo = standard == SQLCipherStandard.V1 ? null : standard.PbkdfAlgo();
            HmacKdfIter = standard.FastKdfIter();
            HmacSaltMask = standard.HmacSaltMask();
        }

        /// <summary>
        /// Creates new instance with user-defined params
        /// </summary>
        /// <param name="kdfIter">Key derivation iterations count</param>
        /// <param name="kdfAlgo">Key derivation algo</param>
        /// <param name="pageSize">SQLCipher db page size</param>
        /// <param name="hmacKdfIter"></param>
        /// <param name="hmacSaltMask"></param>
        /// <exception cref="ArgumentException"></exception>
        public SQLCipherCryptEng(int kdfIter, HashAlgorithmName kdfAlgo, ushort pageSize, HashAlgorithmName hmacKdfAlgo, int hmacKdfIter = SQLCipherStandardExt.FastPbkdf2Iter, byte hmacSaltMask = SQLCipherStandardExt.DefaultHmacSaltMask)
        {
            if (kdfIter < 1)
            {
                throw new ArgumentException(message: "Incorrect key KDF iterations value, must be at least 1");
            }
            if (hmacKdfIter < 1)
            {
                throw new ArgumentException(message: "Incorrect HMAC KDF iterations value, must be at least 1");
            }
            var logVal = Math.Log2(pageSize);
            var delta = logVal - Math.Truncate(logVal);
            if (pageSize < 512 || delta != 0.0)
            {
                //pageSize > 65536 is checked by type
                throw new ArgumentException(message: "Incorrect page size " + pageSize + ". Expected power of two from 512 (2^9) to 65536(2^16)");
            }            
            KdfIter = kdfIter;
            var algo = SQLCipherHashAlgoExt.From(kdfAlgo);
            PbkdfAlgo = algo ?? throw new ArgumentException(message: "Incorrect PBKDF hash algo. Acceptable algos: SHA1, SHA256, SHA512");
            PageSize = pageSize;
            algo = SQLCipherHashAlgoExt.From(hmacKdfAlgo);
            HmacPbkdfAlgo = algo ?? throw new ArgumentException(message: "Incorrect HMAC PBKDF hash algo. Acceptable algos: SHA1, SHA256, SHA512");
            HmacKdfIter = hmacKdfIter;
            HmacSaltMask = hmacSaltMask;
        }

        /*Not working without SQLite pre-encoding reserve space at the end of page (IV + HMAC). Without it corrupts plain-text database page data
        /// <summary>
        /// Encrypts sqlite database with passphrase through key derivation
        /// </summary>
        /// <param name="sqlite">Plain-text SQLite database stream</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>SQLCipher DB</returns>
        public byte[] Encode(BinaryReader sqlite, string passphrase)
        {
            var salt = SQLCipherUtil.GenerateSalt();
            var key = SQLCipherUtil.GenerateKey(salt, passphrase, KdfIter, PbkdfAlgo.HashAlg(), Constants.KeySize);

            return Encode(sqlite, key, salt);
        }

        /// <summary>
        /// Encrypts plaint-text SQLite database with cipher key
        /// </summary>
        /// <param name="sqlite">Plain-text SQLite database stream</param>
        /// <param name="keyBytes">Cipher key</param>
        /// <returns>SQLCipher DB</returns>
        public byte[] Encode(BinaryReader sqlite, byte[] keyBytes)
        {
            var salt = SQLCipherUtil.GenerateSalt();

            return Encode(sqlite, keyBytes, salt);
        }

        /// <summary>
        /// Encrypts plaint-text SQLite database with cipher key and salt bytes
        /// </summary>
        /// <param name="sqlite">Plain-text SQLite database stream</param>
        /// <param name="keyBytes">Cipher key</param>
        /// <param name="salt">Cipher salt</param>
        /// <returns>SQLCipher DB</returns>
        /// <exception cref="ArgumentException"></exception>
        private byte[] Encode(BinaryReader sqlite, byte[] keyBytes, byte[] salt)
        {
            var header = sqlite.ReadBytes(Constants.SQLiteHeader.Length);
            if (SQLCipherUtil.IsEncrypted(header))
            {
                throw new ArgumentException(message: "Possible database has already been encrypted or invalid file data provided");
            }
            if (salt.Length != Constants.SaltSize)
            {
                throw new ArgumentException(message: "Salt must have " + Constants.SaltSize.ToString() + " bytes, but was " + salt.Length.ToString());
            }
            var hmacSalt = new byte[salt.Length];
            for (var k = 0; k < hmacSalt.Length; k++)
            {
                hmacSalt[k] = (byte)(salt[k] ^ HmacSaltMask);
            }
            if (keyBytes.Length != Constants.KeySize)
            {
                throw new ArgumentException(message: "Cryptographic key must have " + Constants.KeySize.ToString() + " bytes, but was " + keyBytes.Length.ToString());
            }
            uint pageSize = (uint)BinaryPrimitives.ReadUInt16BigEndian(sqlite.ReadBytes(2));
            if (pageSize < 512 || pageSize > 65536)
            {
                throw new InvalidDataException(message: "Incorrect SQLite page size " + pageSize.ToString() + ". Expected values from 512 to 65536");
            }
            sqlite.BaseStream.Position -= 2;

            var aesEng = Aes.Create();
            aesEng.Mode = CipherMode.CBC;
            aesEng.KeySize = Constants.KeySize * 8;
            aesEng.Padding = PaddingMode.None;
            aesEng.Key = keyBytes;

            int reserveSize = ReservePageSize;
            var blockSize = aesEng.BlockSize / 8;
            reserveSize = (reserveSize % blockSize) == 0 ? reserveSize : ((reserveSize / blockSize) + 1) * blockSize;
            var sqlCipherPageIndex = 1;

            var writer = new MemoryStream();
            //Encrypt 1st custom page
            var pageBytes = new byte[PageSize];
            Array.Copy(salt, pageBytes, salt.Length);
            var input = sqlite.ReadBytes(pageBytes.Length);
            aesEng.GenerateIV();
            Array.Copy(aesEng.IV, sourceIndex: 0, pageBytes, destinationIndex: pageBytes.Length - reserveSize, aesEng.IV.Length);
            var encryptor = aesEng.CreateEncryptor();
            var readCount = encryptor.TransformBlock(input, inputOffset: 0, inputCount: pageBytes.Length - salt.Length - reserveSize, pageBytes, outputOffset: salt.Length);
            var finalBlock = encryptor.TransformFinalBlock(input, readCount, inputCount: input.Length - readCount);
            if (finalBlock.Length != 0)
            {
                //Array.Copy(finalBlock, sourceIndex: 0, pageBytes, destinationIndex: salt.Length + readCount, finalBlock.Length);
            }
            encryptor.Dispose();
            
            var hmacAlgo = HmacPbkdfAlgo;
            var hmacKey = new byte[Constants.KeySize];
            if (hmacAlgo != null)
            {                
                hmacKey = SQLCipherUtil.GenerateKey(hmacSalt, keyBytes, HmacKdfIter, hmacAlgo.Value.HashAlg(), Constants.KeySize);
                var hmac = SQLCipherUtil.GeneratePageHMAC(hmacKey, pageBytes, sqlCipherPageIndex, reserveSize, hmacAlgo.Value);
                Array.Copy(hmac, sourceIndex: 0, pageBytes, destinationIndex: pageBytes.Length - reserveSize + aesEng.IV.Length, hmac.Length);
            }
            sqlCipherPageIndex++;
            writer.Write(pageBytes, offset: 0, pageBytes.Length);

            while (sqlite.BaseStream.Position < sqlite.BaseStream.Length)
            {
                pageBytes = new byte[PageSize];
                input = sqlite.ReadBytes(pageBytes.Length);
                aesEng.GenerateIV();
                Array.Copy(aesEng.IV, sourceIndex: 0, pageBytes, destinationIndex: pageBytes.Length - reserveSize, aesEng.IV.Length);
                encryptor = aesEng.CreateEncryptor();
                readCount = encryptor.TransformBlock(input, inputOffset: 0, inputCount: input.Length - reserveSize, pageBytes, outputOffset: 0);
                finalBlock = encryptor.TransformFinalBlock(input, readCount, inputCount: input.Length - readCount);
                if (finalBlock.Length != 0)
                {
                    //Array.Copy(finalBlock, sourceIndex: 0, pageBytes, destinationIndex: readCount, finalBlock.Length);
                }
                encryptor.Dispose();
               
                hmacAlgo = HmacPbkdfAlgo;
                if (hmacAlgo != null)
                {
                    var hmac = SQLCipherUtil.GeneratePageHMAC(hmacKey, pageBytes, sqlCipherPageIndex, reserveSize, hmacAlgo.Value);
                    Array.Copy(hmac, sourceIndex: 0, pageBytes, destinationIndex: pageBytes.Length - reserveSize + aesEng.IV.Length, hmac.Length);
                }
                sqlCipherPageIndex++;
                writer.Write(pageBytes, offset: 0, pageBytes.Length);
            }
            var bytes = writer.ToArray();
            writer.Close();

            return bytes;
        }
        */

        /// <summary>
        /// Decrypts SQLCipher encrypted database with passphrase through key derivation
        /// </summary>
        /// <param name="sqlcipher">SQLCipher data stream</param>
        /// <param name="passphrase">Decryption passphrase</param>
        /// <returns>Decrypted SQLite DB</returns>
        public byte[] Decode(BinaryReader sqlcipher, string passphrase)
        {
            var salt = sqlcipher.ReadBytes(Constants.SaltSize);//first 16 bytes of 1st page - salt
            sqlcipher.BaseStream.Position = 0;
            var key = SQLCipherUtil.GenerateKey(salt, passphrase, KdfIter, PbkdfAlgo.HashAlg(), Constants.KeySize);

            return Decode(sqlcipher, key);
        }

        /// <summary>
        /// Decrypts sqlcipher encrypted database with cipher key bytes
        /// </summary>
        /// <param name="sqlcipher">SQLCipher data stream</param>
        /// <param name="keyBytes">Cipher key</param>
        /// <returns>Decrypted SQLite DB</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="UnauthorizedAccessException"></exception>
        public byte[] Decode(BinaryReader sqlcipher, byte[] keyBytes)
        {
            var salt = sqlcipher.ReadBytes(Constants.SaltSize);//first 16 bytes of 1st page - salt
            if (SQLCipherUtil.IsDecrypted(salt))
            {
                throw new CryptographicException(message: "SQLite DB already decrypted");
            }
            sqlcipher.BaseStream.Position = 0;
            if (keyBytes.Length != Constants.KeySize)
            {
                throw new ArgumentException(message: "Cryptographic key must have " + Constants.KeySize.ToString() + " bytes, but was " + keyBytes.Length.ToString());
            }

            var aesEng = Aes.Create();
            aesEng.Mode = CipherMode.CBC;
            aesEng.KeySize = Constants.KeySize * 8;
            aesEng.Padding = PaddingMode.None;
            aesEng.Key = keyBytes;
            
            var hmacSalt = new byte[salt.Length];
            for (var k = 0; k < hmacSalt.Length; k++)
            {
                hmacSalt[k] = (byte)(salt[k] ^ HmacSaltMask);
            }
            int reserveSize = ReservePageSize;
            var blockSize = aesEng.BlockSize / 8;
            reserveSize = (reserveSize % blockSize) == 0 ? reserveSize : ((reserveSize / blockSize) + 1) * blockSize;
            var pageBytes = sqlcipher.ReadBytes(PageSize);
            
            var iv = new byte[Constants.IVSize];//16 bytes after enc content on each page - IV            
            Array.Copy(pageBytes, sourceIndex: pageBytes.Length - reserveSize, iv, destinationIndex: 0, iv.Length);
            aesEng.IV = iv;
            var input = new byte[pageBytes.Length - Constants.SaltSize - reserveSize];
            Array.Copy(pageBytes, sourceIndex: Constants.SaltSize, input, 0, input.Length);

            var sqlCipherPageIndex = 1;
            var hmacKey = Array.Empty<byte>();
            var hmacAlgo = HmacPbkdfAlgo;
            if (hmacAlgo != null)
            {
                hmacKey = SQLCipherUtil.GenerateKey(hmacSalt, keyBytes, HmacKdfIter, PbkdfAlgo.HashAlg(), Constants.KeySize);
                var hmacCheck = SQLCipherUtil.CheckPageHMAC(hmacKey, pageBytes, sqlCipherPageIndex, reserveSize, hmacAlgo.Value);
                if (!hmacCheck)
                {
                    throw new UnauthorizedAccessException(message: "Page data at index " + sqlCipherPageIndex.ToString() + " hasn't passed HMAC check (tampered or corrupted)");
                }
            }

            var decodedWriter = new MemoryStream();
            decodedWriter.Write(Encoding.UTF8.GetBytes(Constants.SQLiteHeader));
            var buffer = new byte[PageSize];
            int readCount;
            //Decrypt the custom 1st page
            var decryptor = aesEng.CreateDecryptor();
            readCount = decryptor.TransformBlock(input, inputOffset: 0, inputCount: input.Length, buffer, outputOffset: 0);
            var finalBlock = decryptor.TransformFinalBlock(input, readCount, inputCount: input.Length - readCount);
            decryptor.Dispose();
            decodedWriter.Write(buffer, offset: 0, readCount);            
            if (finalBlock.Length != 0)
            {
                decodedWriter.Write(finalBlock, offset: 0, finalBlock.Length);
            } 
            decodedWriter.Write(new byte[PageSize - readCount - Constants.SaltSize - finalBlock.Length]);            

            //Decrypt the next pages
            while (sqlcipher.BaseStream.Position < sqlcipher.BaseStream.Length)
            {
                buffer = new byte[PageSize];
                pageBytes = sqlcipher.ReadBytes(PageSize);
                iv = new byte[Constants.IVSize];
                Array.Copy(pageBytes, sourceIndex: pageBytes.Length - reserveSize, iv, destinationIndex: 0, iv.Length);
                aesEng.IV = iv;
                input = new byte[pageBytes.Length - reserveSize];
                Array.Copy(pageBytes, input, input.Length);
                hmacAlgo = HmacPbkdfAlgo;
                if (hmacAlgo != null)
                {
                    sqlCipherPageIndex++;
                    var hmacCheck = SQLCipherUtil.CheckPageHMAC(hmacKey, pageBytes, sqlCipherPageIndex, reserveSize, hmacAlgo.Value);
                    if (!hmacCheck)
                    {
                        throw new UnauthorizedAccessException(message: "Page data at index " + sqlCipherPageIndex.ToString() + " hasn't passed HMAC check (tampered or corrupted)");
                    }                    
                }
                decryptor = aesEng.CreateDecryptor();
                readCount = decryptor.TransformBlock(input, inputOffset: 0, inputCount: input.Length, buffer, outputOffset: 0);
                finalBlock = decryptor.TransformFinalBlock(input, readCount, inputCount: input.Length - readCount);
                decryptor.Dispose();
                decodedWriter.Write(buffer, offset: 0, readCount);
                if (finalBlock.Length != 0)
                {
                    decodedWriter.Write(finalBlock, offset: 0, finalBlock.Length);
                }
                decodedWriter.Write(new byte[PageSize - readCount - finalBlock.Length]);
            }
            var decrypted = decodedWriter.ToArray();
            decodedWriter.Close();

            return decrypted;
        }
    }
}
