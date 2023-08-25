using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;

namespace SQLCipherED.Tests
{
    public class UnitDecryptStandardV4Test
    {
        [Test]
        public void DecryptWithHexKey()
        {
            var reader = new BinaryReader(File.OpenRead("db-v4-hexkey.sqlcipher"));
            var key = Enumerable.Range(0, Constants.DbHexKeyStr.Length)
                            .Where(x => x % 2 == 0)
                            .Select(x => Convert.ToByte(Constants.DbHexKeyStr.Substring(x, 2), 16))
                            .ToArray();
            var decoder = new SQLCipherCryptEng(standard: SQLCipherStandard.V4);
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
        public void DecryptWithPassphrase()
        {
            var reader = new BinaryReader(File.OpenRead("db-v4-passphrase.sqlcipher"));
            var decoder = new SQLCipherCryptEng(standard: SQLCipherStandard.V4);
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
    }
}