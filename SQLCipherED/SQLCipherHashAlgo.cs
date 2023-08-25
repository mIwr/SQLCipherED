using System.Security.Cryptography;

namespace SQLCipherED
{
    public enum SQLCipherHashAlgo: byte
    {
        SHA1, SHA256, SHA512
    }

    public static class SQLCipherHashAlgoExt
    {
        public static SQLCipherHashAlgo? From(HashAlgorithmName algName)
        {
            var name = algName.Name ?? string.Empty;
            if (name == HashAlgorithmName.SHA1.Name)
            {
                return SQLCipherHashAlgo.SHA1;
            }
            if (name == HashAlgorithmName.SHA256.Name)
            {
                return SQLCipherHashAlgo.SHA256;
            }
            if (name == HashAlgorithmName.SHA512.Name)
            {
                return SQLCipherHashAlgo.SHA512;
            }

            return null;
        }

        public static HashAlgorithmName HashAlg(this SQLCipherHashAlgo algo)
        {
            switch (algo)
            {
                case SQLCipherHashAlgo.SHA1: return HashAlgorithmName.SHA1;
                case SQLCipherHashAlgo.SHA256: return HashAlgorithmName.SHA256;
                case SQLCipherHashAlgo.SHA512: return HashAlgorithmName.SHA512;
            }

            return HashAlgorithmName.SHA1;
        }

        public static byte Size(this SQLCipherHashAlgo algo)
        {
            switch (algo)
            {
                case SQLCipherHashAlgo.SHA1: return SQLCipherStandardExt.SHA1Size;
                case SQLCipherHashAlgo.SHA256: return SQLCipherStandardExt.SHA256Size;
                case SQLCipherHashAlgo.SHA512: return SQLCipherStandardExt.SHA512Size;
            }

            return 0;
        }
    }
}
