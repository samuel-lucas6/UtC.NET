using System.Security.Cryptography;

namespace UtCDotNet;

public static class CX
{
    public const int BlockSize = 16;
    
    // https://github.com/rozbb/kc-aeads/blob/main/src/cx_prf.rs
    // https://github.com/brycx/CAEAD/blob/main/src/kc/mod.rs#L101
    public static void Derive(Span<byte> commitment, Span<byte> subKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        if (commitment.Length != BlockSize && commitment.Length != BlockSize * 2) { throw new ArgumentOutOfRangeException(nameof(commitment), commitment.Length, $"{nameof(commitment)} must be {BlockSize} or {BlockSize * 2} bytes long."); }
        if (subKey.Length != BlockSize && subKey.Length != BlockSize * 2) { throw new ArgumentOutOfRangeException(nameof(subKey), subKey.Length, $"{nameof(subKey)} must be {BlockSize} or {BlockSize * 2} bytes long."); }
        if (nonce.Length >= BlockSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be less than {BlockSize} bytes long."); }
        if (key.Length != BlockSize && key.Length != BlockSize * 2) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {BlockSize} or {BlockSize * 2} bytes long."); }
        
        int blockCount = commitment.Length / BlockSize + subKey.Length / BlockSize;
        Span<byte> blocks = stackalloc byte[BlockSize * blockCount]; blocks.Clear();
        for (int i = 0; i < blockCount; i++) {
            Span<byte> block = blocks.Slice(i * BlockSize, BlockSize);
            nonce.CopyTo(block);
            block[^1] = (byte)(i + 1);
        }
        
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        Span<byte> ciphertext = stackalloc byte[blocks.Length];
        aes.EncryptEcb(blocks, ciphertext, PaddingMode.None);
        
        for (int i = 0; i < BlockSize; i++) {
            ciphertext[i] ^= blocks[i];
        }
        
        ciphertext[..commitment.Length].CopyTo(commitment);
        ciphertext[commitment.Length..].CopyTo(subKey);
        
        CryptographicOperations.ZeroMemory(blocks);
        CryptographicOperations.ZeroMemory(ciphertext);
    }
}