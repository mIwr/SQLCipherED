using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;

namespace SQLCipherED.Tests
{
    public class UnitDecryptCustomKdfAlgoTest
    {
        [Test]
        public void DecryptCustomKdfAlgoWithHexKey()
        {
            var reader = new BinaryReader(File.OpenRead("db-hexkey-custom-kdfalgo.sqlcipher"));
            var key = Enumerable.Range(0, Constants.DbHexKeyStr.Length)
                            .Where(x => x % 2 == 0)
                            .Select(x => Convert.ToByte(Constants.DbHexKeyStr.Substring(x, 2), 16))
                            .ToArray();
            var decoder = new SQLCipherCryptEng(kdfIter: SQLCipherStandard.V4.KdfIter(),
                kdfAlgo: Constants.CustomKdfAlgo,
                pageSize: SQLCipherStandard.V4.PageSize(),
                hmacKdfAlgo: SQLCipherStandard.V4.PbkdfAlgoName());
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
        public void TestCustomKdfAlgoWithHexKeyAffect()
        {
            var reader = new BinaryReader(File.OpenRead("db-hexkey-custom-kdfalgo.sqlcipher"));
            var key = Enumerable.Range(0, Constants.DbHexKeyStr.Length)
                            .Where(x => x % 2 == 0)
                            .Select(x => Convert.ToByte(Constants.DbHexKeyStr.Substring(x, 2), 16))
                            .ToArray();
            var decoder = new SQLCipherCryptEng(kdfIter: SQLCipherStandard.V4.KdfIter(),
                kdfAlgo: Constants.IncorrectCustomKdfAlgo,
                pageSize: SQLCipherStandard.V4.PageSize(),
                hmacKdfAlgo: SQLCipherStandard.V4.PbkdfAlgoName());
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
        public void DecryptCustomKdfAlgoWithPassphrase()
        {
            var reader = new BinaryReader(File.OpenRead("db-passphrase-custom-kdfalgo.sqlcipher"));
            var decoder = new SQLCipherCryptEng(kdfIter: SQLCipherStandard.V4.KdfIter(),
                kdfAlgo: Constants.CustomKdfAlgo,
                pageSize: SQLCipherStandard.V4.PageSize(),
                hmacKdfAlgo: SQLCipherStandard.V4.PbkdfAlgoName());
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
        public void TestCustomKdfAlgoWithPassphraseAffect()
        {
            var reader = new BinaryReader(File.OpenRead("db-passphrase-custom-kdfalgo.sqlcipher"));
            var decoder = new SQLCipherCryptEng(kdfIter: SQLCipherStandard.V4.KdfIter(),
                kdfAlgo: Constants.IncorrectCustomKdfAlgo,
                pageSize: SQLCipherStandard.V4.PageSize(),
                hmacKdfAlgo: SQLCipherStandard.V4.PbkdfAlgoName());
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