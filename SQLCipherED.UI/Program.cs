using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

namespace SQLCipherED.UI
{
    class Program
    {        
        private const string _helpTitle = "SQLcipher DB standlone decryptor";
        private const string _helpText = "Usage: runner-sqlcipher-ed -i [dbSource] [-p [passphrase] or -b [hexString]] {-o [outputPath] -v [sqlCipherVersion] -ps [pageSize] -ka [keyKdfAlgo] -ki [keyKdfIter] -ha [hmacKdfAlgo] }\n\n" +
            "-i [Database source] - SQLCipher source path\n" +
            "-p [Passphrase] - Encrypt/decrypt passphrase\n" +
            "-b [Hex string cipher key] - Cipher key hex string. Must have 32 bytes (64 hex-chars). Overrides defined passphrase\n" +
            "-o [Output file path] - Output path. Default value - {Source}.sqlite\n" + 
            "-v [SQLCipher standard version] - SQLCipher default encrypt/decrypt params according standard version. Acceptable values: 1,2,3,4. Default value - 4\n" +
            "-ps [Page size] - SQLCipher cipher page size (PRAGMA cipher_page_size analogue). Overrides default value of standard version. Must be a power of two between 512 and 65536 inclusive\n" +
            "-ka [Kdf algo] - The key derivation algorithm to use for computing an encryption/decryption key (PRAGMA cipher_kdf_algorithm analogue). Overrides default value of standard version. Acceptable values: sha512 (PBKDF2_HMAC_SHA512), sha256 (PBKDF2_HMAC_SHA256), sha1 (PBKDF2_HMAC_SHA1)\n" +
            "-ki [Kdf iterations] - PBKDF2 key derivation iterations count (PRAGMA kdf_iter analogue). Overrides default value of standard version\n" +
            "-ha [HMAC algo] - The HMAC algorithm used for both HMAC and key derivation (PRAGMA cipher_hmac_algorithm analogue). Overrides default value of standard version and -ka parameter. Acceptable values: sha512 (HMAC_SHA512), sha256 (HMAC_SHA256), sha1 (HMAC_SHA1) \n" +
            "-h - Show this message\n";

        static string _sourcePath = string.Empty;
        static string _passphrase = string.Empty;
        static byte[] _hexKey = Array.Empty<byte>();
        static string _outPath = string.Empty;
        static ushort _pageSize = 0;
        static int _kdfIter = 0;
        static HashAlgorithmName _kdfAlgo = HashAlgorithmName.MD5;

        static void Main(string[] args)
        {
            var parseStatus = ProcessArgs(args);
            if (parseStatus)
            {                
                var sqlcipherCryptEng = new SQLCipherCryptEng(_kdfIter, _kdfAlgo, _pageSize, _kdfAlgo);
                var reader = new BinaryReader(File.OpenRead(_sourcePath));
                var outData = Array.Empty<byte>();
                Console.WriteLine("Decrypting '" + _sourcePath + '\'');
                try
                {
                    if (_hexKey.Length != 0)
                    {
                        outData = sqlcipherCryptEng.Decode(reader, _hexKey);
                    }
                    else
                    {
                        outData = sqlcipherCryptEng.Decode(reader, _passphrase);
                    }
                    Console.WriteLine("Done");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }               
                reader.Close();
                if (outData.Length != 0)
                {
                    File.WriteAllBytes(_outPath, outData);
                }                
            }
#if DEBUG
            Console.ReadKey();
#endif
        }

        static bool ProcessArgs(string[] args)
        {
            if (args.Length == 0)
            {
                return ProcessArgs(new string[] { "-h" });
            }
            SQLCipherStandard standard = SQLCipherStandard.V4;
            HashAlgorithmName hmacAlgo = HashAlgorithmName.MD5;

            var currParamIndex = 0;
            while (currParamIndex < args.Length)
            {
                var param = args[currParamIndex++];
                if (param == "-h")
                {
                    var assemblyName = Assembly.GetExecutingAssembly().GetName();
                    var version = assemblyName.Version?.ToString() ?? "UnknownVersion";
                    var text = _helpTitle + ' ' + version + "\n\n" + _helpText;
                    Console.WriteLine(text);
                    return false;
                }
                if (param.Length >= 4)
                {
                    Console.WriteLine("Warning: unknown parameter name '" + param + '\'');
                    continue;
                }
                if (currParamIndex >= args.Length)
                {
                    Console.WriteLine("Warning: no value for parameter '" + param + '\'');
                    break;
                }
                var paramValue = args[currParamIndex++];
                switch (param)
                {
                    case "-i":
                        _sourcePath = paramValue;
                        if (!File.Exists(_sourcePath))
                        {
                            Console.WriteLine("Error: file '" + _sourcePath + "' doesn't exist");
                            return false;
                        }
                        continue;
                    case "-p":
                        _passphrase = paramValue;
                        continue;
                    case "-b":
                        _hexKey = Enumerable.Range(0, paramValue.Length)
                            .Where(x => x % 2 == 0)
                            .Select(x => Convert.ToByte(paramValue.Substring(x, 2), 16))
                            .ToArray();
                        continue;
                    case "-v":
                        if (!byte.TryParse(paramValue, out var versionNumber))
                        {
                            Console.WriteLine("Warning unable parse SQLCipher version from " + paramValue.ToString() + ". Used default value");
                            continue;
                        }
                        var parsed = SQLCipherStandardExt.From(versionNumber);
                        if (parsed == null)
                        {
                            Console.WriteLine("Warning unable parse SQLCipher version from " + paramValue.ToString() + ". Used default value");
                            continue;                            
                        }
                        standard = parsed.Value;
                        continue;
                    case "-o":
                        _outPath = paramValue;
                        continue;
                    case "-ps":
                        if (!ushort.TryParse(paramValue, out _pageSize))
                        {
                            Console.WriteLine("Warning: unable to parse page size from '" + paramValue + '\'');
                        }
                        continue;
                    case "-ka":
                        if (!HashAlgorithmName.TryFromOid(paramValue, out _kdfAlgo))
                        {
                            Console.WriteLine("Warning: unable to parse key KDF algo from " + paramValue);
                        }
                        continue;
                    case "-ki":
                        if (!int.TryParse(paramValue, out _kdfIter))
                        {
                            Console.WriteLine("Warning: unable to parse key KDF iterations from " + paramValue);
                        }
                        continue;
                    case "-ha":
                        if (!HashAlgorithmName.TryFromOid(paramValue, out hmacAlgo))
                        {
                            Console.WriteLine("Warning: unable to parse HMAC KDF algo from " + paramValue);
                        }
                        continue;
                    default:
                        Console.WriteLine("Warning: unknown parameter name '" + param + '\'');
                        continue;
                }                
            }
            if (string.IsNullOrEmpty(_sourcePath))
            {
                Console.WriteLine("Not stated input source database");
                return false;
            }
            if (string.IsNullOrEmpty(_outPath))
            {
                _outPath = _sourcePath + ".sqlite";
            }
            if (string.IsNullOrEmpty(_passphrase) && _hexKey.Length == 0)
            {
                Console.WriteLine("Error: not stated passphrase or hex key");
                return false;
            }
            if (_pageSize == 0)
            {                
                _pageSize = standard.PageSize();
                Console.WriteLine("Info: not stated page size, used from default standard value - " + _pageSize.ToString() + " bytes");
            }
            if (_kdfIter == 0)
            {
                _kdfIter = standard.KdfIter();
                Console.WriteLine("Info: not stated cipher key KDF derivation iterations count, used from default standard value - " + _kdfIter.ToString());
            }
            if (_kdfAlgo.Name?.ToLower() == "md5")
            {
                if (hmacAlgo.Name?.ToLower() == "md5")
                {                    
                    _kdfAlgo = standard.PbkdfAlgoName();
                    Console.WriteLine("Info: not stated cipher key KDF algo, used from default standard value - " + standard.PbkdfAlgo().ToString());
                }
                else
                {
                    _kdfAlgo = hmacAlgo;
                }
            }

            return true;
        }
    }
}
