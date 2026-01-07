using System;
using System.Security.Cryptography;

namespace SQLCipherED
{

    /// <summary>
    /// Represents default SQLCipher settings
    /// </summary>
    public enum SQLCipherStandard : byte
    {
        /// <summary>
        /// Revision 1 - no tag (0 bytes)
        /// </summary>
        V1 = 1,
        /// <summary>
        /// Revision 2 - SHA1 tag (20 bytes)
        /// </summary>
        V2 = 2, 
        /// <summary>
        /// Revision 3 - SHA1 tag (20 bytes)
        /// </summary>
        V3 = 3,
        /// <summary>
        /// Revision 4 - SHA512 (64 bytes) or optionally SHA256 (32 bytes) tag
        /// </summary>
        V4 = 4
    }

    /// <summary>
    /// Default SQLCipher settings extension
    /// </summary>
    public static class SQLCipherStandardExt
    {
        internal const byte SHA1Size = 20;
        internal const byte SHA256Size = 32;
        internal const byte SHA512Size = 64;

        internal const ushort PageSizeV1V2V3 = 1024;
        internal const ushort PageSizeV4 = 4096;

        internal const int Kdf2IterV1V2 = 4000;
        internal const int Kdf2IterV3 = 64000;
        internal const int Kdf2IterV4 = 256000;

        internal const byte FastPbkdf2Iter = 2;
        internal const byte DefaultHmacSaltMask = 0x3a;

        /// <summary>
        /// Tries to parse SQLCipher revision standard from number
        /// </summary>
        /// <param name="versionNumber">Version number</param>
        /// <returns>SQLCipher revision standard. Optional</returns>
        public static SQLCipherStandard? From(byte versionNumber)
        {            
            switch(versionNumber)
            {
                case 1: return SQLCipherStandard.V1;
                case 2: return SQLCipherStandard.V2;
                case 3: return SQLCipherStandard.V3;
                case 4: return SQLCipherStandard.V4;
            }

            return null;
        }

        /// <summary>
        /// Default key derivation iterations count
        /// </summary>
        /// <param name="standard">SQLCipher revision standard</param>
        /// <returns></returns>
        public static int KdfIter(this SQLCipherStandard standard)
        {
            switch(standard)
            {
                case SQLCipherStandard.V3: return Kdf2IterV3;
                case SQLCipherStandard.V4: return Kdf2IterV4;
                default: return Kdf2IterV1V2;
            }
        }

        /// <summary>
        /// Default fast key derivation iterations count
        /// </summary>
        /// <param name="standard">SQLCipher revision standard</param>
        /// <returns></returns>
        public static int FastKdfIter(this SQLCipherStandard standard)
        {
            return FastPbkdf2Iter;
        }

        /// <summary>
        /// Default key derivation .NET hash algo
        /// </summary>
        /// <param name="standard">SQLCipher revision standard</param>
        /// <returns></returns>
        public static HashAlgorithmName PbkdfAlgoName(this SQLCipherStandard standard)
        {
            switch (standard)
            {
                case SQLCipherStandard.V4: return HashAlgorithmName.SHA512;
                default: return HashAlgorithmName.SHA1;
            }
        }

        /// <summary>
        /// Default key derivation SQLCipher hash algo
        /// </summary>
        /// <param name="standard">SQLCipher revision standard</param>
        /// <returns></returns>
        public static SQLCipherHashAlgo PbkdfAlgo(this SQLCipherStandard standard)
        {
            switch(standard)
            {
                case SQLCipherStandard.V4: return SQLCipherHashAlgo.SHA512;
                default: return SQLCipherHashAlgo.SHA1;
            }
        }

        /// <summary>
        /// Default SQLCipher data page size in bytes
        /// </summary>
        /// <param name="standard">SQLCipher revision standard</param>
        /// <returns></returns>
        public static ushort PageSize(this SQLCipherStandard standard)
        {
            switch(standard)
            {                
                case SQLCipherStandard.V4: return PageSizeV4;
                default: return PageSizeV1V2V3;
            }
        }

        /// <summary>
        /// SQLCipher HMAC salt mask magic byte
        /// </summary>
        /// <param name="standard">SQLCipher revision standard</param>
        /// <returns></returns>
        public static byte HmacSaltMask(this SQLCipherStandard standard)
        {
            return DefaultHmacSaltMask;
        }
     }
}
