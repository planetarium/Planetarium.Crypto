using Microsoft.VisualStudio.TestTools.UnitTesting;
using Planetarium.CryptoTests;
using System.Text;

namespace Planetarium.Crypto.Encrypt.Tests
{
    [TestClass()]
    public class AESGCMTests
    {
        [TestMethod()]
        public void DecryptTest()
        {
            var key = "349c469e0ea9eb8822658aaf0817a221d7fd4be78b243f455d72b60f9b1a3a4e".ParseHex();
            var ciphertext = "1881342a2930cdc2734ae15e143a09fe5b0a5f113b0e2fcfc8d56f23c508a2890d7139c592cf4e4c76758a9b2317cb94".ParseHex();
            var expected = Encoding.ASCII.GetBytes("a secret message");
            var aes = new AESGCM(key);
            var actual = aes.Decrypt(ciphertext);
            CollectionAssert.AreEqual(expected, actual);
        }
    }
}