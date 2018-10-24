using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Planetarium.Crypto.Encrypt;
using System;
using System.Linq;

namespace Planetarium.Crypto.Keys
{
    public class PrivateKey
    {
        internal readonly ECPrivateKeyParameters keyParam;
        private PrivateKey(ECPrivateKeyParameters keyParam)
        {
            this.keyParam = keyParam;
        }
        internal static ECDomainParameters GetECParameters()
        {
            return GetECParameters("secp256k1");
        }
        internal static ECDomainParameters GetECParameters(string name)
        {
            var ps = SecNamedCurves.GetByName(name);
            return new ECDomainParameters(ps.Curve, ps.G, ps.N, ps.H);
        }
        public static PrivateKey FromBytes(byte[] bs)
        {
            var ecParams = GetECParameters();
            var keyParam = new ECPrivateKeyParameters(
                "ECDSA", new BigInteger(1, bs), ecParams
            );

            return new PrivateKey(keyParam);
        }
        public static PrivateKey Generate()
        {
            var gen = new ECKeyPairGenerator();
            var secureRandom = new SecureRandom();
            var ecParams = GetECParameters();
            var keyGenParam = new ECKeyGenerationParameters(ecParams, secureRandom);
            gen.Init(keyGenParam);

            return new PrivateKey(gen.GenerateKeyPair().Private as ECPrivateKeyParameters);
        }
        public PublicKey PublicKey
        {
            get
            {
                var ecParams = PrivateKey.GetECParameters();
                var q = ecParams.G.Multiply(this.keyParam.D);
                var keyParam = new ECPublicKeyParameters("ECDSA", q, ecParams) as ECPublicKeyParameters;
                return new PublicKey(keyParam);
            }
        }

        public byte[] Bytes
        {
            get
            {
                return keyParam.D.ToByteArrayUnsigned();
            }
        }

        public byte[] Sign(byte[] payload)
        {
            return Sign(payload, "SHA256withECDSA");
        }

        public byte[] Sign(byte[] payload, string algorithm)
        {
            var signer = SignerUtilities.GetSigner(algorithm);
            signer.Init(true, keyParam);
            signer.BlockUpdate(payload, 0, payload.Length);
            return signer.GenerateSignature();
        }

        public byte[] Decrypt(byte[] payload)
        {
            var pubKey = PublicKey.FromBytes(payload.Take(33).ToArray());
            var aesKey = ECDH(pubKey);
            var aes = new AESGCM(aesKey);

            return aes.Decrypt(payload, 33);
        }

        private ECPoint CalculatePoint(ECPublicKeyParameters pubKeyParams)
        {
            var dp = keyParam.Parameters;
            if (!dp.Equals(pubKeyParams.Parameters))
                throw new InvalidOperationException("ECDH public key has wrong domain parameters");

            var d = keyParam.D;

            ECPoint Q = ECAlgorithms.CleanPoint(dp.Curve, pubKeyParams.Q);
            if (Q.IsInfinity)
                throw new InvalidOperationException("Infinity is not a valid public key for ECDH");

            BigInteger h = dp.H;
            if (!h.Equals(BigInteger.One))
            {
                d = dp.HInv.Multiply(d).Mod(dp.N);
                Q = ECAlgorithms.ReferenceMultiply(Q, h);
            }

            ECPoint P = Q.Multiply(d).Normalize();
            if (P.IsInfinity)
                throw new InvalidOperationException("Infinity is not a valid agreement value for ECDH");

            return P;
        }

        public byte[] ECDH(PublicKey publicKey)
        {
            var P = CalculatePoint(publicKey.keyParam);
            var x = P.AffineXCoord.ToBigInteger();
            var y = P.AffineYCoord.ToBigInteger();

            var xbuf = x.ToByteArrayUnsigned();
            var ybuf = y.TestBit(0) ? new byte[] { 0x03 } : new byte[] { 0x02 };

            var hash = new Sha256Digest();
            var result = new byte[hash.GetDigestSize()];

            hash.BlockUpdate(ybuf, 0, ybuf.Length);
            hash.BlockUpdate(xbuf, 0, xbuf.Length);
            hash.DoFinal(result, 0);

            return result;
        }
    }

    public class PublicKey
    {
        internal ECPublicKeyParameters keyParam;
        internal PublicKey(ECPublicKeyParameters keyParam)
        {
            this.keyParam = keyParam;
        }
        public static PublicKey FromBytes(byte[] bs)
        {
            var ecParams = PrivateKey.GetECParameters();
            var keyParam = new ECPublicKeyParameters("ECDSA", ecParams.Curve.DecodePoint(bs), ecParams);

            return new PublicKey(keyParam);
        }
        public byte[] Format(bool compress)
        {
            return keyParam.Q.GetEncoded(compress);
        }

        public bool Verify(byte[] payload, byte[] signature)
        {
            return Verify(payload, signature, "SHA256withECDSA");
        }

        public bool Verify(byte[] payload, byte[] signature, string algorithm)
        {
            var verifier = SignerUtilities.GetSigner(algorithm);
            verifier.Init(false, keyParam);
            verifier.BlockUpdate(payload, 0, payload.Length);

            return verifier.VerifySignature(signature);
        }

        public byte[] Encrypt(byte[] payload)
        {
            var disposablePrivateKey = PrivateKey.Generate();
            var aesKey = disposablePrivateKey.ECDH(this);
            var aes = new AESGCM(aesKey);

            return aes.Encrypt(payload, disposablePrivateKey.PublicKey.Format(true));
        }
    }

}
