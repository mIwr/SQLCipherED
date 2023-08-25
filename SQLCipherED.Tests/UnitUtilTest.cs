using System.IO;

namespace SQLCipherED.Tests
{
    public class UnitUtilTest
    {
        [Test]
        public void TestPlainDb()
        {
            var bytes = File.ReadAllBytes("plain.sqlite");
            var actual = SQLCipherUtil.IsDecrypted(bytes);
            Assert.That(actual, Is.True);
            actual = SQLCipherUtil.IsEncrypted(bytes);
            Assert.That(actual, Is.False);
        }

        [Test]
        public void TestSQLCipherDb()
        {
            var bytes = File.ReadAllBytes("db-v4-hexkey.sqlcipher");
            var actual = SQLCipherUtil.IsDecrypted(bytes);
            Assert.That(actual, Is.False);
            actual = SQLCipherUtil.IsEncrypted(bytes);
            Assert.That(actual, Is.True);
        }
    }
}
