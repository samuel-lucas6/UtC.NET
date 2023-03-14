using Microsoft.VisualStudio.TestTools.UnitTesting;
using UtCDotNet;

namespace UtCDotNetTests;

[TestClass]
public class CXTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "f2b02c474458649f6a3334d944278190",
            "306c92755683e9f9b581363e19177cb0",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        };
        yield return new object[]
        {
            "f2b02c474458649f6a3334d944278190",
            "306c92755683e9f9b581363e19177cb0bab84a7130836d7a968cbbb921a2b92d",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        };
        yield return new object[]
        {
            "f2b02c474458649f6a3334d944278190306c92755683e9f9b581363e19177cb0",
            "bab84a7130836d7a968cbbb921a2b92d9de8d6351875518bc3dbcd72f120d797",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        };
    }
    
    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { CX.BlockSize + 1, CX.BlockSize, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.BlockSize - 1, CX.BlockSize, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.BlockSize + 1, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.BlockSize - 1, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.BlockSize, CX.BlockSize, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.BlockSize, UtC.NonceSize, UtC.KeySize - 1 };
        yield return new object[] { CX.BlockSize, CX.BlockSize, UtC.NonceSize, CX.BlockSize - 1 };
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Derive_Valid(string commitment, string subKey, string nonce, string key)
    {
        Span<byte> c = Convert.FromHexString(commitment);
        Span<byte> s = Convert.FromHexString(subKey);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        
        CX.Derive(c, s, n, k);
        
        Assert.AreEqual(commitment, Convert.ToHexString(c).ToLower());
        Assert.AreEqual(subKey, Convert.ToHexString(s).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Derive_Invalid(int commitmentSize, int subKeySize, int nonceSize, int keySize)
    {
        var c = new byte[commitmentSize];
        var s = new byte[subKeySize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CX.Derive(c, s, n, k));
    }
}