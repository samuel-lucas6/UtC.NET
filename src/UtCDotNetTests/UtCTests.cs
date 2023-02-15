using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using UtCDotNet;

namespace UtCDotNetTests;

[TestClass]
public class UtCTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "7116e3341578167a056d43b09371c72a4c5b6f66ac546099687494f391a2152858b4cac42510ce4567357ee08506ef1b0935b3197f20386b975cbf8e43826975410c46245623eaedb450fcf72dfef04406c0fbfc85f9ec80566b00be07dcc262879f6f0eb11144865c03cc47e384440070143d06fc70a05d29b4c109d24c0b0f4b5e2fc21f8cef8500cef780a1001de1b44953838ee39ad23109507d484155be31a2",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }
    
    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize - 1, 0, UtC.NonceSize, UtC.KeySize, UtC.CommitmentSize };
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize, 1, UtC.NonceSize, UtC.KeySize, UtC.CommitmentSize };
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize, 0, UtC.NonceSize + 1, UtC.KeySize, UtC.CommitmentSize };
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize, 0, UtC.NonceSize - 1, UtC.KeySize, UtC.CommitmentSize };
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize, 0, UtC.NonceSize, UtC.KeySize + 1, UtC.CommitmentSize };
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize, 0, UtC.NonceSize, UtC.KeySize - 1, UtC.CommitmentSize };
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[p.Length + UtC.CommitmentSize + UtC.TagSize];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        
        UtC.Encrypt(c, p, n, k, a);
        
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
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => UtC.Encrypt(c, p, n, k, a));
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> p = stackalloc byte[c.Length - UtC.CommitmentSize - UtC.TagSize];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        
        UtC.Decrypt(p, c, n, k, a);
        
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
        var p = new byte[parameters[0].Length - UtC.CommitmentSize - UtC.TagSize];
        
        foreach (var param in parameters) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => UtC.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => UtC.Decrypt(p, c, n, k, a));
    }
}