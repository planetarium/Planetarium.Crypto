using System;

namespace Planetarium.Crypto.Extension
{
    public static class HexExtension
    {
        public static byte[] ParseHex(this string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length / 2; i++) bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                return bytes;
        }

        public static string Hex(this byte[] bs)
        {
            return BitConverter.ToString(bs).Replace("-", "").ToLower();
        }
    }
}
