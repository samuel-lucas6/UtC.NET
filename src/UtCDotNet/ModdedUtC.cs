/*
    UtC.NET: Bellare and Hoang's UtC and HtE[UtC] transforms using ChaCha20-Poly1305 and BLAKE2b.
    Copyright (c) 2023 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System.Security.Cryptography;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace UtCDotNet;

public static class ModdedUtC
{
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int NonceSize = ChaCha20Poly1305.NonceSize;
    public const int TagSize = ChaCha20Poly1305.TagSize;
    public const int CommitmentSize = BLAKE2b.TagSize;
    
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        
        Span<byte> prfOutput = stackalloc byte[BLAKE2b.MaxHashSize];
        Span<byte> commitment = prfOutput[..CommitmentSize], subKey = prfOutput[CommitmentSize..];
        BLAKE2b.ComputeTag(prfOutput, nonce, key);
        
        commitment.CopyTo(ciphertext[..CommitmentSize]);
        ChaCha20Poly1305.Encrypt(ciphertext[CommitmentSize..], plaintext, nonce, subKey, associatedData);
        CryptographicOperations.ZeroMemory(prfOutput);
    }
    
    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        
        Span<byte> prfOutput = stackalloc byte[BLAKE2b.MaxHashSize];
        Span<byte> commitment = prfOutput[..CommitmentSize], subKey = prfOutput[CommitmentSize..];
        BLAKE2b.ComputeTag(prfOutput, nonce, key);
        
        if (!ConstantTime.Equals(commitment, ciphertext[..CommitmentSize])) {
            CryptographicOperations.ZeroMemory(prfOutput);
            throw new CryptographicException();
        }
        
        ChaCha20Poly1305.Decrypt(plaintext, ciphertext[CommitmentSize..], nonce, subKey, associatedData);
        CryptographicOperations.ZeroMemory(prfOutput);
    }
}