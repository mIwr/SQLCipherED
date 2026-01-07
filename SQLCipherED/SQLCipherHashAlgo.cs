using System.Security.Cryptography;

namespace SQLCipherED
{
    /// <summary>
    /// SQLCipher hash algo
    /// </summary>
    public enum SQLCipherHashAlgo: byte
    {
        /// <summary>
        /// SHA1
        /// </summary>
        SHA1, 
        /// <summary>
        /// SHA256
        /// </summary>
        SHA256,
        /// <summary>
        /// SHA512
        /// </summary>
        SHA512
    }

    /// <summary>
    /// SQLCipher hash algo extension
    /// </summary>
    public static class SQLCipherHashAlgoExt
    {
        /// <summary>
        /// Tries to parse SQLCipher hash algo from .NET hash algo
        /// </summary>
        /// <param name="algName">.NET hash algo name</param>
        /// <returns></returns>
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

        /// <summary>
        /// .NET hash algo
        /// </summary>
        /// <param name="algo">SQLCipher hash algo</param>
        /// <returns></returns>
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

        /// <summary>
        /// Hash size
        /// </summary>
        /// <param name="algo">SQLCipher hash algo</param>
        /// <returns></returns>
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
