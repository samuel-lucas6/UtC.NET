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

namespace UtCDotNet;

public static class HtE
{
    public const int KeySize = UtC.KeySize;
    public const int NonceSize = UtC.NonceSize;
    public const int TagSize = UtC.TagSize;
    public const int CommitmentSize = UtC.CommitmentSize;
    
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        
        Span<byte> subKey = stackalloc byte[KeySize];
        DeriveKey(subKey, nonce, key, associatedData);
        UtC.Encrypt(ciphertext, plaintext, nonce, subKey, associatedData: Span<byte>.Empty);
        CryptographicOperations.ZeroMemory(subKey);
    }
    
    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        
        Span<byte> subKey = stackalloc byte[KeySize];
        DeriveKey(subKey, nonce, key, associatedData);
        UtC.Decrypt(plaintext, ciphertext, nonce, subKey, associatedData: Span<byte>.Empty);
        CryptographicOperations.ZeroMemory(subKey);
    }
    
    private static void DeriveKey(Span<byte> subKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData)
    {
        using var blake2b = new IncrementalBLAKE2b(subKey.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Finalize(subKey);
    }
}