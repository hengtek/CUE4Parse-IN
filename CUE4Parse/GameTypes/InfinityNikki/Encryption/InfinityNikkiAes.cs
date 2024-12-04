using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CUE4Parse.UE4.VirtualFileSystem;
using AesProvider = CUE4Parse.Encryption.Aes.Aes;
using Org.BouncyCastle.Utilities;

namespace CUE4Parse.GameTypes.InfinityNikki.Encryption;

public static class InfinityNikkieAes
{
    public static byte[] InfinityNikkieDecrypt(byte[] bytes, int beginOffset, int count, bool isIndex, IAesVfsReader reader)
    {
        if (bytes.Length < beginOffset + count)
            throw new IndexOutOfRangeException("beginOffset + count is larger than the length of bytes");
        if (count % 16 != 0)
            throw new ArgumentException("count must be a multiple of 16");
        if (reader.AesKey == null)
            throw new NullReferenceException("reader.AesKey");

        var output = AesProvider.Decrypt(bytes, beginOffset, count, reader.AesKey);

        for (var i = 0; i < count >> 4; i++)
        {
            output[i * 16] ^= reader.AesKey.Key[0];
            output[i * 16 + 15] ^= reader.AesKey.Key[reader.AesKey.Key.Length - 1];
        }

        return output;
    }
}
