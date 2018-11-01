using Microsoft.VisualStudio.TestTools.UnitTesting;
using Planetarium.Crypto.Extension;
using System.Linq;
using System.Text;

namespace Planetarium.Crypto.Keys.Tests
{
    [TestClass()]
    public class PrivateKeyTests
    {
        [TestMethod()]
        public void FromBytesTest()
        {
            var bs = "98669850728c6c410bf42c45fe7c49232d14cfb55b784d8135ae404c7c243fc7".ParseHex();
            var key = PrivateKey.FromBytes(bs);
        }

        [TestMethod()]
        public void BytesTest()
        {
            var bs = "98669850728c6c410bf42c45fe7c49232d14cfb55b784d8135ae404c7c243fc7".ParseHex();
            var key = PrivateKey.FromBytes(bs);
            Assert.IsTrue(bs.SequenceEqual(key.Bytes));
        }

        [TestMethod()]
        public void PublicKeyTest()
        {
            var key = PrivateKey.FromBytes("82fc9947e878fc7ed01c6c310688603f0a41c8e8704e5b990e8388343b0fd465".ParseHex());
            var expected = "04c7c674a223661faefed8515febacc411c0f3569c10c65ec86cdce4d85c7ea26c617f0cf19ce0b10686501e57af1a7002282fefa52845be2267d1f4d7af322974".ParseHex();
            var actual = key.PublicKey.Format(false);

            CollectionAssert.AreEquivalent(expected, actual);

        }

        [TestMethod()]
        public void GenerateTest()
        {
            PrivateKey.Generate();
        }

        [TestMethod()]
        public void SignTest()
        {
            var pk = PrivateKey.FromBytes("520938fae079789561268c2933f636d8b5a0011ea04112dbababf295e5ddef88".ParseHex());
            var payload = "64373a616374696f6e736c6531303a7075626c69635f6b657936353a04b5a24aa2112720423bad39a0205182379d6f2b33e3487c9ab6cc8fc496f8a5483440efbbef0657ac2ef6c6ee05db06a94532fda7ddc44a1695e5ce1a3d3c76db393a726563697069656e7432303a8ae72efab09594665112e6d49dfd1941538cf374363a73656e64657232303ab6c03de57ddf0369c7207d2d113adff8205199cf393a74696d657374616d7032373a323031382d30312d30325430333a30343a30352e3030363030305a65".ParseHex();
            var expected = "3044022062cf8a04419c6a03baf55de10d9b200edaa9df2b9bf0cf989fd65d71c55c356002202aa55969d0adb15e9e708d8300e105311e1a16165db73ed8f4f0051d9f1381fd".ParseHex();
            var actual = pk.Sign(payload);

            CollectionAssert.AreEqual(expected, actual);
        }

        [TestMethod()]
        public void ECDHtest()
        {
            var prvKey = PrivateKey.FromBytes("82fc9947e878fc7ed01c6c310688603f0a41c8e8704e5b990e8388343b0fd465".ParseHex());
            var pubKey = PrivateKey.FromBytes("5f706787ac72c1080275c1f398640fb07e9da0b124ae9734b28b8d0f01eda586".ParseHex()).PublicKey;

            var expected = "5935d0476af9df2998efb60383adf2ff23bc928322cfbb738fca88e49d557d7e".ParseHex();
            var actual = prvKey.ECDH(pubKey);

            CollectionAssert.AreEqual(expected, actual);
        }

        [TestMethod()]
        public void DecryptTest()
        {
            var prvKey = PrivateKey.FromBytes("fbc20042b3a707a7d5a1fa577171f49cd3a9e67ab9295757c714e3f2f8c2d573".ParseHex());
            var cipherText = "03e31a0dea31e2b1327bd8700ad357cc69314ecad70ae2e4fa5517a33b67cfb1c4faa110d4d27311eff14799d73d3caaa20e357c41c88e1422c764edcce06c06b58644c168a5abf39dcb46b6e2".ParseHex();
            var expected = Encoding.ASCII.GetBytes("test message");

            CollectionAssert.AreEqual(prvKey.Decrypt(cipherText), expected);
        }
    }
}