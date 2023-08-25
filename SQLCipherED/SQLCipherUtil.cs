using System;
using System.Security.Cryptography;
using System.Text;

namespace SQLCipherED
{
    public static class SQLCipherUtil
    {
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

        public static bool IsDecrypted(byte[] sqlcipherBytes)
        {
            return !IsEncrypted(sqlcipherBytes);
        }

        public static byte[] GenerateSalt()
        {
            var salt = RandomNumberGenerator.GetBytes(Constants.SaltSize);
            return salt;
        }

        public static byte[] GenerateKey(byte[] salt, byte[] passBytes, int kdfIter, HashAlgorithmName hashAlgo, byte keySize)
        {
            var key = Rfc2898DeriveBytes.Pbkdf2(passBytes, salt, kdfIter, hashAlgo, keySize);

            return key;
        }

        public static byte[] GenerateKey(byte[] salt, string passphrase, int kdfIter, HashAlgorithmName hashAlgo, byte keySize)
        {
            var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, kdfIter, hashAlgo, keySize);

            return key;
        }

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
}