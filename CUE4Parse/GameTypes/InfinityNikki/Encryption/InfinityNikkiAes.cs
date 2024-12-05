using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CUE4Parse.UE4.VirtualFileSystem;
using AesProvider = CUE4Parse.Encryption.Aes.Aes;
using Org.BouncyCastle.Utilities;

namespace CUE4Parse.GameTypes.InfinityNikki.Encryption;

public static class InfinityNikkiAes
{
    public static byte[] InfinityNikkiDecrypt(byte[] bytes, int beginOffset, int count, bool isIndex, IAesVfsReader reader)
    {
        if (bytes.Length < beginOffset + count)
            throw new IndexOutOfRangeException("beginOffset + count is larger than the length of bytes");
        if (count % 16 != 0)
            throw new ArgumentException("count must be a multiple of 16");
        if (reader.AesKey == null)
            throw new NullReferenceException("reader.AesKey");

        var output = AesProvider.Decrypt(bytes, beginOffset, count, reader.AesKey);

        output = PostDecryptData(output, count, reader.AesKey.Key);

        return output;
    }

    public static byte[] PostDecryptData(byte[] bytes, int count, byte[] key)
    {
        for (var i = 0; i < count >> 4; i++)
        {
            bytes[i * 16] ^= key[0];
            bytes[i * 16 + 15] ^= key[^1];
        }

        return bytes;
    }
}
