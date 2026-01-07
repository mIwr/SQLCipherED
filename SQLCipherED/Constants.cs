namespace SQLCipherED
{
    /// <summary>
    /// SQLCipher constants
    /// </summary>
    internal static class Constants
    {
        /// <summary>
        /// Plain-text SQLite DB magic header
        /// </summary>
        internal const string SQLiteHeader = "SQLite format 3\0";
        /// <summary>
        /// SQLCipher salt size in bytes
        /// </summary>
        internal const byte SaltSize = 16;
        /// <summary>
        /// SQLCipher AES IV size in bytes
        /// </summary>
        internal const byte IVSize = 16;
        /// <summary>
        /// SQLCipher decrptyion key size in bytes
        /// </summary>
        internal const byte KeySize = 32;        
    }
}
