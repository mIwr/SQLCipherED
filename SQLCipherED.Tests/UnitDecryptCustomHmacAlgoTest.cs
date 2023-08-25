using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;

namespace SQLCipherED.Tests
{
    public class UnitDecryptCustomHmacAlgoTest
    {
        [Test]
        public void DecryptCustomHmacAlgoWithHexKey()
        {
            var reader = new BinaryReader(File.OpenRead("db-hexkey-custom-hmacalgo.sqlcipher"));
            var key = Enumerable.Range(0, Constants.DbHexKeyStr.Length)
                            .Where(x => x % 2 == 0)
                            .Select(x => Convert.ToByte(Constants.DbHexKeyStr.Substring(x, 2), 16))
                            .ToArray();
            var decoder = new SQLCipherCryptEng(kdfIter: SQLCipherStandard.V4.KdfIter(),
                kdfAlgo: SQLCipherStandard.V4.PbkdfAlgoName(),
                pageSize: SQLCipherStandard.V4.PageSize(),
                hmacKdfAlgo: Constants.CustomHmacAlgo);
            var decoded = decoder.Decode(reader, key);
            reader.Close();
            reader.Dispose();
            
            var status = SQLCipherUtil.IsDecrypted(decoded);
            Assert.That(status, Is.True);
            var bytes = new byte[2];
            Array.Copy(decoded, sourceIndex: 16, bytes, destinationIndex: 0, bytes.Length);
            var pageSize = BinaryPrimitives.ReadUInt16BigEndian(bytes);
            Assert.That(pageSize, Is.EqualTo(SQLCipherStandard.V4.PageSize()));            
        }

        [Test]
        public void TestCustomHmacAlgoWithHexKeyAffect()
        {
            var reader = new BinaryReader(File.OpenRead("db-hexkey-custom-hmacalgo.sqlcipher"));
            var key = Enumerable.Range(0, Constants.DbHexKeyStr.Length)
                            .Where(x => x % 2 == 0)
                            .Select(x => Convert.ToByte(Constants.DbHexKeyStr.Substring(x, 2), 16))
                            .ToArray();
            var decoder = new SQLCipherCryptEng(kdfIter: SQLCipherStandard.V4.KdfIter(),
                kdfAlgo: SQLCipherStandard.V4.PbkdfAlgoName(),
                pageSize: SQLCipherStandard.V4.PageSize(),
                hmacKdfAlgo: Constants.IncorrectCustomHmacAlgo);
            var exceptionFired = false;
            try
            {
                var decoded = decoder.Decode(reader, Constants.DbPassphrase);
            }
            catch
            {
                exceptionFired = true;
            }
            reader.Close();
            reader.Dispose();

            Assert.That(exceptionFired, Is.True);
        }

        [Test]
        public void DecryptCustomHmacAlgoWithPassphrase()
        {
            var reader = new BinaryReader(File.OpenRead("db-passphrase-custom-hmacalgo.sqlcipher"));
            var decoder = new SQLCipherCryptEng(kdfIter: SQLCipherStandard.V4.KdfIter(),
                kdfAlgo: SQLCipherStandard.V4.PbkdfAlgoName(),
                pageSize: SQLCipherStandard.V4.PageSize(),
                hmacKdfAlgo: Constants.CustomHmacAlgo);
            var decoded = decoder.Decode(reader, Constants.DbPassphrase);
            reader.Close();
            reader.Dispose();

            var status = SQLCipherUtil.IsDecrypted(decoded);
            Assert.That(status, Is.True);
            var bytes = new byte[2];
            Array.Copy(decoded, sourceIndex: 16, bytes, destinationIndex: 0, bytes.Length);
            var pageSize = BinaryPrimitives.ReadUInt16BigEndian(bytes);
            Assert.That(pageSize, Is.EqualTo(SQLCipherStandard.V4.PageSize()));
        }

        [Test]
        public void TestCustomHmacAlgoWithPassphraseAffect()
        {
            var reader = new BinaryReader(File.OpenRead("db-passphrase-custom-hmacalgo.sqlcipher"));
            var decoder = new SQLCipherCryptEng(kdfIter: SQLCipherStandard.V4.KdfIter(),
                kdfAlgo: SQLCipherStandard.V4.PbkdfAlgoName(),
                pageSize: SQLCipherStandard.V4.PageSize(),
                hmacKdfAlgo: Constants.IncorrectCustomHmacAlgo);
            var exceptionFired = false;
            try
            {
                var decoded = decoder.Decode(reader, Constants.DbPassphrase);                
            }
            catch
            {
                exceptionFired = true;
            }
            reader.Close();
            reader.Dispose();

            Assert.That(exceptionFired, Is.True);
        }
    }
}