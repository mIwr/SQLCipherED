using System.Security.Cryptography;

namespace SQLCipherED.Tests
{
    internal static class Constants
    {
        internal const string DbHexKeyStr = "A3727521DD1CCB2C23BB68EDF1AB4911AFE9DE9C11105F676B65500644DD23C2";
        internal const string DbPassphrase = "p@ssw0rd";
        internal const ushort CustomKdfIter = 64000;
        internal const ushort IncorrectCustomKdfIter = CustomKdfIter + 1024;
        internal static readonly HashAlgorithmName CustomKdfAlgo = HashAlgorithmName.SHA256;
        internal static readonly HashAlgorithmName IncorrectCustomKdfAlgo = HashAlgorithmName.SHA1;
        internal static readonly HashAlgorithmName CustomHmacAlgo = HashAlgorithmName.SHA256;
        internal static readonly HashAlgorithmName IncorrectCustomHmacAlgo = HashAlgorithmName.SHA512;
    }
}
