using System;
using System.Security.Cryptography;
using System.Text;

namespace SQLCipherED
{
    /// <summary>
    /// SQLCipher utils
    /// </summary>
    public static class SQLCipherUtil
    {
        /// <summary>
        /// Checks the database bytes (encrypted/decrypted)
        /// </summary>
        /// <param name="sqlcipherBytes">Raw DB bytes</param>
        /// <returns>Returns False, if the database in hex starts from magic header, otherwise - True</returns>
        public static bool IsEncrypted(byte[] sqlcipherBytes)
        {
            if (sqlcipherBytes.Length < Constants.SQLiteHeader.Length)
            {
                return false;
            }
            byte[] header = new byte[Constants.SQLiteHeader.Length];
            Array.Copy(sqlcipherBytes, header, header.Length);
            var plainHeaderBytes = Encoding.UTF8.GetBytes(Constants.SQLiteHeader);
            for (var i = 0; i < header.Length; i++)
            {
                if (header[i] != plainHeaderBytes[i])
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Checks the data base bytes (encrypted/decrypted)
        /// </summary>
        /// <param name="sqlcipherBytes">Raw DB bytes</param>
        /// <returns>>Returns True, if the database in hex starts from magic header, otherwise - False</returns>
        public static bool IsDecrypted(byte[] sqlcipherBytes)
        {
            return !IsEncrypted(sqlcipherBytes);
        }

        /// <summary>
        /// Generates randomized salt for SQLCipher encryption/decryption ops
        /// </summary>
        /// <returns>Salt bytes</returns>
        public static byte[] GenerateSalt()
        {
            var rnd = RandomNumberGenerator.Create();
            var salt = new byte[Constants.SaltSize];
            rnd.GetBytes(salt);
            return salt;
        }

        /// <summary>
        /// Generates SQLCipher encryption/decryption key
        /// </summary>
        /// <param name="salt">Salt</param>
        /// <param name="passBytes">Passphrase bytes</param>
        /// <param name="kdfIter">Result key derrivation iterations count</param>
        /// <param name="hashAlgo">Result key derrivation hash algo</param>
        /// <param name="keySize">Result key size</param>
        /// <returns></returns>
        public static byte[] GenerateKey(byte[] salt, byte[] passBytes, int kdfIter, HashAlgorithmName hashAlgo, byte keySize)
        {
#if NET
            var key = Rfc2898DeriveBytes.Pbkdf2(passBytes, salt, kdfIter, hashAlgo, keySize);
#else
            var key = PBKDF2.DeriveBytes(hashAlgo.Name, salt, passBytes, kdfIter, keySize);
#endif
            return key;
        }

        /// <summary>
        /// Generates SQLCipher encryption/decryption key
        /// </summary>
        /// <param name="salt">Salt</param>
        /// <param name="passphrase">Passhrase string</param>
        /// <param name="kdfIter">Result key derrivation iterations count</param>
        /// <param name="hashAlgo">Result key derrivation hash algo</param>
        /// <param name="keySize">Result key size</param>
        /// <returns></returns>
        public static byte[] GenerateKey(byte[] salt, string passphrase, int kdfIter, HashAlgorithmName hashAlgo, byte keySize)
        {
#if NET
            var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, kdfIter, hashAlgo, keySize);
#else
            var passBytes = Encoding.UTF8.GetBytes(passphrase);
            var key = PBKDF2.DeriveBytes(hashAlgo.Name, salt, passBytes, kdfIter, keySize);
#endif
            return key;
        }

        /// <summary>
        /// Generates SQLCipher data page HMAC
        /// </summary>
        /// <param name="hmacKey">HMAC key</param>
        /// <param name="pageBytes">Page data raw bytes</param>
        /// <param name="sqlCipherPageIndex">Page index</param>
        /// <param name="reserveSize">IV + HMAC (if exists) bytes count at the end of page</param>
        /// <param name="hmacAlgo">SQLCipher HMAC algo</param>
        /// <returns>Returns generated HMAC of the page data</returns>
        /// <exception cref="CryptographicException">Throws, when unable to convert SQLCipher hash algo to .NET hash algo</exception>
        public static byte[] GeneratePageHMAC(byte[] hmacKey, byte[] pageBytes, int sqlCipherPageIndex, int reserveSize, SQLCipherHashAlgo hmacAlgo)
        {
            HMAC hmac;
            switch (hmacAlgo)
            {
                case SQLCipherHashAlgo.SHA1:
                    hmac = new HMACSHA1(hmacKey);
                    break;
                case SQLCipherHashAlgo.SHA256:
                    hmac = new HMACSHA256(hmacKey);
                    break;
                case SQLCipherHashAlgo.SHA512:
                    hmac = new HMACSHA512(hmacKey);
                    break;
                default: throw new CryptographicException(message: "Unable to parse hash alg from " + hmacAlgo.ToString() + " instance");
            }
            int offset = sqlCipherPageIndex == 1 ? Constants.SaltSize : 0;
            var hmacData = new byte[pageBytes.Length - offset - reserveSize + Constants.IVSize + 4];
            Array.Copy(pageBytes, sourceIndex: offset, hmacData, destinationIndex: 0, length: hmacData.Length - 4);
            byte[] bytes = BitConverter.GetBytes(sqlCipherPageIndex);
            Array.Copy(bytes, sourceIndex: 0, hmacData, destinationIndex: hmacData.Length - 4, bytes.Length);
            var pageHmac = new byte[hmacAlgo.Size()];
            Array.Copy(pageBytes, sourceIndex: pageBytes.Length - reserveSize + Constants.IVSize, pageHmac, destinationIndex: 0, pageHmac.Length);
            var calculatedHmac = hmac.ComputeHash(hmacData);

            return calculatedHmac;
        }

        /// <summary>
        /// Compares generated and stock checksums of the page
        /// </summary>
        /// <param name="hmacKey">HMAC key</param>
        /// <param name="pageBytes">Raw page bytes</param>
        /// <param name="sqlCipherPageIndex">Page index</param>
        /// <param name="reserveSize">IV + HMAC (if exists) bytes count at the end of page</param>
        /// <param name="hmacAlgo">SQLCipher HMAC algo</param>
        /// <returns>Returns True, if generated and stock checksums are equal, which means correct decryption. Otherwise returns False</returns>
        public static bool CheckPageHMAC(byte[] hmacKey, byte[] pageBytes, int sqlCipherPageIndex, int reserveSize, SQLCipherHashAlgo hmacAlgo)
        {
            var pageHmac = new byte[hmacAlgo.Size()];
            Array.Copy(pageBytes, sourceIndex: pageBytes.Length - reserveSize + Constants.IVSize, pageHmac, destinationIndex: 0, pageHmac.Length);
            var calculatedHmac = GeneratePageHMAC(hmacKey, pageBytes, sqlCipherPageIndex, reserveSize, hmacAlgo);

            if (calculatedHmac.Length != pageHmac.Length)
            {
                return false;
            }
            for (var k = 0; k < calculatedHmac.Length; k++)
            {
                var a = calculatedHmac[k];
                var b = pageHmac[k];
                if (a != b)
                {
                    return false;
                }
            }

            return true;
        }
    }

#if !NET
    #region .NET Standard PBKDF2
    /// <summary>
    /// Provides an easy to understand PBKDF2 implementation.
    /// Note: This will create correct values, but it's very slow.
    /// In security critical applications you want to use <see cref="Rfc2898DeriveBytes"/> instead.
    /// </summary>
    internal static class PBKDF2
    {
        /// <summary>
        /// Derives bytes using PBKDF2
        /// </summary>
        /// <param name="rngFunction">
        /// This is the name of the hash function. Usually SHA1
        /// but can be any other such as (but not exhaustively):
        /// SHA256, SHA512, RIPEMD160.
        /// Any algorithm that has a matching HMAC function will work.
        /// </param>
        /// <param name="salt">
        /// Salt for the function.
        /// This should be randomly generated and be between 16 and 32 bytes.
        /// You need to store this somewhere if you want to create the same hash later.
        /// </param>
        /// <param name="password">
        /// Key for the function.
        /// If your key is a string, use Encoding.UTF8.GetBytes(string) to convert it into a byte array.
        /// </param>
        /// <param name="iterations">
        /// The number of iterations.
        /// Normally you want this to be 100'000 or more,
        /// but this implementation is not made to be fast, but easy to understand.
        /// Keep it around 1'000 - 10'000 for this demo.
        /// </param>
        /// <param name="byteCount">
        /// The number of bytes you want to get out of this function
        /// </param>
        /// <returns>
        /// Randomly looking but deterministic bytes
        /// </returns>
        internal static byte[] DeriveBytes(string rngFunction, byte[] salt, byte[] password, int iterations, int byteCount)
        {
            #region Validation
            //Make sure something was specified
            if (string.IsNullOrEmpty(rngFunction))
            {
                throw new ArgumentException($"'{nameof(rngFunction)}' cannot be null or empty.", nameof(rngFunction));
            }
            //Cannot use null as salt
            if (salt is null)
            {
                throw new ArgumentNullException(nameof(salt));
            }
            //Cannot use null as password either
            if (password is null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            //Require at least one iteration
            if (iterations < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations));
            }
            //Require at least one output byte
            if (byteCount < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(byteCount));
            }
            #endregion

            //Create the HMAC of the supplied algorithm
            var keyHash = HMAC.Create("HMAC" + rngFunction);
            if (keyHash == null)
            {
                return Array.Empty<byte>();
            }

            //Size of the algorithm in bytes.
            //Note that sizes in cryptographic algorithms are often reported in bits, not bytes,
            //hence why we divide the value by 8
            var size = keyHash.HashSize / 8;

            using (keyHash)
            {
                //Number of hash blocks we need to fit the requested byte count
                var BlockCount = byteCount / size;
                //If there is a remainder, we need to add one extra block
                //For example with SHA1 (block size 20 bytes) and 30 bytes of data:
                //30/20=1 (integer division always rounds down)
                //30%20=10 (remainder is not zero, so increase block size by one)
                //Final size: 2 blocks
                //If you prefer this in one line:
                //BlockCount = ByteCount / Size + (ByteCount % Size == 0 ? 0 : 1);
                if (byteCount % size != 0)
                {
                    ++BlockCount;
                }
                //This holds the final output data
                byte[] Output = new byte[byteCount];
                //Set key
                keyHash.Key = password;
                //Hash as many blocks as needed
                for (var BlockIndex = 1; BlockIndex <= BlockCount; BlockIndex++)
                {
                    //Hash a block of data
                    var Round = HashBlock(keyHash, salt, BlockIndex, iterations);
                    //The location of where the data goes in the output
                    //This basically starts each output at the end of the previous one
                    var BlockOffset = (BlockIndex - 1) * size;
                    //Normally we copy all bytes but the last chunk may be smaller
                    var BytesToCopy = Math.Min(Round.Length, byteCount - BlockOffset);
                    Array.Copy(Round, 0, Output, BlockOffset, BytesToCopy);
                }
                return Output;
            }
        }

        /// <summary>
        /// Hashes a block of output data
        /// </summary>
        /// <param name="Hasher">Hash algorithm</param>
        /// <param name="Salt">Salt value</param>
        /// <param name="BlockIndex">Block index (starts at 1, not 0)</param>
        /// <param name="IterationCount">Number of iterations</param>
        /// <returns>Hashed block data</returns>
        private static byte[] HashBlock(KeyedHashAlgorithm Hasher, byte[] Salt, int BlockIndex, int IterationCount)
        {
            //First round is special by additionally using the block index in the input
            byte[] Data = Hasher.ComputeHash(GetFirstBlockData(Salt, BlockIndex));
            //Holds the final result
            byte[] Result = (byte[])Data.Clone();
            //rounds 2 to IterationCount use the result "Data" of the previous run
            for (var i = 2; i <= IterationCount; i++)
            {
                byte[] Temp = Hasher.ComputeHash(Data);
                //The result is XOR combined with the input data
                for (var j = 0; j < Temp.Length; j++)
                {
                    Result[j] ^= Temp[j];
                }
                //Use the last result as the data for the next iteration
                Data = Temp;
            }
            return Result;
        }

        /// <summary>
        /// Gets the value used for the first block hash
        /// </summary>
        /// <param name="Salt">Salt</param>
        /// <param name="BlockIndex">Block index (starts at 1, not 0)</param>
        /// <returns>value for first iteration of the hasher</returns>
        private static byte[] GetFirstBlockData(byte[] Salt, int BlockIndex)
        {
            var Data = new byte[Salt.Length + 4];
            //Copy key into the buffer
            Array.Copy(Salt, Data, Salt.Length);
            //Append the BlockIndex as 32 bit big endian integer
            Data[Salt.Length] = (byte)(BlockIndex >> 24);
            Data[Salt.Length + 1] = (byte)(BlockIndex >> 16 & 0xFF);
            Data[Salt.Length + 2] = (byte)(BlockIndex >> 8 & 0xFF);
            Data[Salt.Length + 3] = (byte)(BlockIndex & 0xFF);
            return Data;
        }
    }
    #endregion
#endif
}