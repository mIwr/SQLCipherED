using System;
using System.Security.Cryptography;

namespace SQLCipherED
{

    /// <summary>
    /// Represents default SQLCipher settings
    /// </summary>
    public enum SQLCipherStandard : byte
    {
        V1 = 1, V2 = 2, V3 = 3, V4 = 4
    }

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

        public static SQLCipherStandard? From(byte versionNumber)
        {
            var values = Enum.GetValues<SQLCipherStandard>();
            foreach (var enumItem in values)
            {
                if ((byte)enumItem != versionNumber)
                {
                    continue;
                }
                return enumItem;
            }

            return null;
        }

        public static int KdfIter (this SQLCipherStandard standard)
        {
            switch(standard)
            {
                case SQLCipherStandard.V3: return Kdf2IterV3;
                case SQLCipherStandard.V4: return Kdf2IterV4;
                default: return Kdf2IterV1V2;
            }
        }

        public static int FastKdfIter(this SQLCipherStandard standard)
        {
            return FastPbkdf2Iter;
        }

        public static HashAlgorithmName PbkdfAlgoName(this SQLCipherStandard standard)
        {
            switch (standard)
            {
                case SQLCipherStandard.V4: return HashAlgorithmName.SHA512;
                default: return HashAlgorithmName.SHA1;
            }
        }

        public static SQLCipherHashAlgo PbkdfAlgo(this SQLCipherStandard standard)
        {
            switch(standard)
            {
                case SQLCipherStandard.V4: return SQLCipherHashAlgo.SHA512;
                default: return SQLCipherHashAlgo.SHA1;
            }
        }

        public static ushort PageSize(this SQLCipherStandard standard)
        {
            switch(standard)
            {                
                case SQLCipherStandard.V4: return PageSizeV4;
                default: return PageSizeV1V2V3;
            }
        }

        public static byte HmacSaltMask(this SQLCipherStandard standard)
        {
            return DefaultHmacSaltMask;
        }
     }
}
