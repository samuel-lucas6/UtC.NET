﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using UtCDotNet;

namespace UtCDotNetTests;

[TestClass]
public class HtETests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "2e54f0644bd89660c673c8569838b15dbc296a59670c208770f31b9e6eaeacb5109fa9755c6a1e07943c1370e27e2d03eb785ac90eeb4405b011c4a9201564d642ac781eaa5e552fe64bbdfd8cbe4bfa513c451b019edd4bb35429dfc8cf28a7cdeb8d001ece2cee7f297758497fe128d357c59cee96b6f1353f8bfee7f795227e9435fe8f1817bf8b52d4db2784fb0aa346",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }
    
    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { HtE.CommitmentSize + HtE.TagSize - 1, 0, HtE.NonceSize, HtE.KeySize, HtE.CommitmentSize };
        yield return new object[] { HtE.CommitmentSize + HtE.TagSize, 1, HtE.NonceSize, HtE.KeySize, HtE.CommitmentSize };
        yield return new object[] { HtE.CommitmentSize + HtE.TagSize, 0, HtE.NonceSize + 1, HtE.KeySize, HtE.CommitmentSize };
        yield return new object[] { HtE.CommitmentSize + HtE.TagSize, 0, HtE.NonceSize - 1, HtE.KeySize, HtE.CommitmentSize };
        yield return new object[] { HtE.CommitmentSize + HtE.TagSize, 0, HtE.NonceSize, HtE.KeySize + 1, HtE.CommitmentSize };
        yield return new object[] { HtE.CommitmentSize + HtE.TagSize, 0, HtE.NonceSize, HtE.KeySize - 1, HtE.CommitmentSize };
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[p.Length + HtE.CommitmentSize + HtE.TagSize];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        
        HtE.Encrypt(c, p, n, k, a);
        
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
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HtE.Encrypt(c, p, n, k, a));
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> p = stackalloc byte[c.Length - HtE.CommitmentSize - HtE.TagSize];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        
        HtE.Decrypt(p, c, n, k, a);
        
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
        var p = new byte[parameters[0].Length - HtE.CommitmentSize - HtE.TagSize];
        
        foreach (var param in parameters) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => HtE.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HtE.Decrypt(p, c, n, k, a));
    }
}