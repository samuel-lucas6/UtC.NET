using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using UtCDotNet;

namespace UtCDotNetTests;

[TestClass]
public class ModdedHtETests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "38ad3a48df6519f0f8785fbdfa7ca6f4144a9f1e82279b95b22f4c5ef18cc4135baba3e4e67bea635097086a0851192e3ba3615821fad63e9a8a7b6fa6a473bd4665bd2b56e4d4bfbb9bed87c0137f33eead29321f1a062a3162fc4215a7b314ffaacc83aa7dde8d2db318c863c0031f5739b04e49f90651f3888a24a5c9f8a0a12908be72e34f5ef1a1e657d887e213330e6c4eec588d17bc92651a156a96ad55bb",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }
    
    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { ModdedHtE.CommitmentSize + ModdedHtE.TagSize - 1, 0, ModdedHtE.NonceSize, ModdedHtE.KeySize, ModdedHtE.CommitmentSize };
        yield return new object[] { ModdedHtE.CommitmentSize + ModdedHtE.TagSize, 1, ModdedHtE.NonceSize, ModdedHtE.KeySize, ModdedHtE.CommitmentSize };
        yield return new object[] { ModdedHtE.CommitmentSize + ModdedHtE.TagSize, 0, ModdedHtE.NonceSize + 1, ModdedHtE.KeySize, ModdedHtE.CommitmentSize };
        yield return new object[] { ModdedHtE.CommitmentSize + ModdedHtE.TagSize, 0, ModdedHtE.NonceSize - 1, ModdedHtE.KeySize, ModdedHtE.CommitmentSize };
        yield return new object[] { ModdedHtE.CommitmentSize + ModdedHtE.TagSize, 0, ModdedHtE.NonceSize, ModdedHtE.KeySize + 1, ModdedHtE.CommitmentSize };
        yield return new object[] { ModdedHtE.CommitmentSize + ModdedHtE.TagSize, 0, ModdedHtE.NonceSize, ModdedHtE.KeySize - 1, ModdedHtE.CommitmentSize };
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[p.Length + ModdedHtE.CommitmentSize + ModdedHtE.TagSize];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        
        ModdedHtE.Encrypt(c, p, n, k, a);
        
        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var a = new byte[associatedDataSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ModdedHtE.Encrypt(c, p, n, k, a));
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> p = stackalloc byte[c.Length - ModdedHtE.CommitmentSize - ModdedHtE.TagSize];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        
        ModdedHtE.Decrypt(p, c, n, k, a);
        
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(nonce),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };
        var p = new byte[parameters[0].Length - ModdedHtE.CommitmentSize - ModdedHtE.TagSize];
        
        foreach (var param in parameters) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => ModdedHtE.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
            param[0]--;
        }
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var a = new byte[associatedDataSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ModdedHtE.Decrypt(p, c, n, k, a));
    }
}