using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.IO;

namespace Planetarium.Crypto.Encrypt
{
    public class AESGCM
    {
        private const int KEY_BIT_SIZE = 256;
        private const int MAC_BIT_SIZE = 128;
        private const int NONCE_BIT_SIZE = 128;

        private readonly SecureRandom secureRandom;
        private readonly byte[] key;

        public AESGCM(byte[] key)
        {
            secureRandom = new SecureRandom();

            if (key == null || key.Length != KEY_BIT_SIZE / 8)
            {
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KEY_BIT_SIZE), "key");
            }
            this.key = key;
        }

        public byte[] Encrypt(byte[] message, byte[] nonSecret = null)
        {
            var nonce = new byte[NONCE_BIT_SIZE / 8];
            secureRandom.NextBytes(nonce, 0, nonce.Length);

            nonSecret = nonSecret ?? new byte[] { };

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), MAC_BIT_SIZE, nonce, nonSecret);
            cipher.Init(true, parameters);

            var cipherText = new byte[cipher.GetOutputSize(message.Length)];
            var len = cipher.ProcessBytes(message, 0, message.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    binaryWriter.Write(nonSecret);
                    binaryWriter.Write(nonce);
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }

        public byte[] Decrypt(byte[] encrypted, int nonSecretLength = 0)
        {
            if (encrypted == null || encrypted.Length == 0)
            {
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            }

            using (var cipherStream = new MemoryStream(encrypted))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                var nonSecretPayload = cipherReader.ReadBytes(nonSecretLength);
                var nonce = cipherReader.ReadBytes(NONCE_BIT_SIZE / 8);

                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(key), MAC_BIT_SIZE, nonce, nonSecretPayload);
                cipher.Init(false, parameters);

                var cipherText = cipherReader.ReadBytes(encrypted.Length - nonSecretLength - nonce.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];

                try
                {
                    var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                    cipher.DoFinal(plainText, len);
                    return plainText;
                }
                catch (InvalidCipherTextException)
                {
                    return null;
                }
            }
        }
    }
}
