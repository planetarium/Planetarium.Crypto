using Microsoft.VisualStudio.TestTools.UnitTesting;
using Planetarium.CryptoTests;
using System.Text;

namespace Planetarium.Crypto.Keys.Tests
{
    [TestClass()]
    public class PublicKeyTests
    {
        [TestMethod()]
        public void VerifyTest()
        {
            var pubKey = PublicKey.FromBytes("02ce214f186fd39941665f4aa79ac6f3d8ab4de42c5a31e78be46877ed12350ab9".ParseHex());
            var payload = Encoding.ASCII.GetBytes("hello world");
            var signature = "3045022100aaa0d710ba87fafefb401fbe6b801108368f5d32e4ac82e62ca360ec08f0989b02207c4aa573b52e4326426acc6efd92ed4a36da561520c50cea27e583a2df7ca620".ParseHex();
            Assert.IsTrue(pubKey.Verify(payload, signature));
        }

        [TestMethod()]
        public void EncryptTest()
        {
            var prvKey = PrivateKey.Generate();
            var pubKey = prvKey.PublicKey;
            var bs = Encoding.ASCII.GetBytes("hello world");
            var encrypted = pubKey.Encrypt(bs);

            CollectionAssert.AreEqual(bs, prvKey.Decrypt(encrypted));
        }
    }
}