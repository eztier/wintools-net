using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace wintools {

  class EncryptionProvider {
    private byte[] key;
    private byte[] iv;
    private ICryptoTransform transform;
    private ICryptoTransform decryptTransform;

    private byte[] GetBase64FromHexString(string input) {
      List<string> byteStrings = new List<string>();

      for (int i = 0; i < input.Length; i += 2) {
        byteStrings.Add(input.Substring(i, 2));
      }
      byte[] bytes = new byte[byteStrings.Count];

      for (int index = 0; index < bytes.Length; index++) {
        // Perform the conversion.            
        bytes[index] = byte.Parse(byteStrings[index], System.Globalization.NumberStyles.AllowHexSpecifier);
      }
      return bytes;
    }

    private void GetSharedSecret(ref byte[] key, ref byte[] iv) {
      using (wintools.UnmanagedEncryption encryption = new UnmanagedEncryption()) {
        try {
          string secret = encryption.DoGetSharedSecret();
          string[] s = secret.Split('\x20');
          key = GetBase64FromHexString(s[0]);
          iv = GetBase64FromHexString(s[1]);
        } catch { }
      }
    }

    private void CreateCrytoTransform() {
      // Get shared secret
      GetSharedSecret(ref key, ref iv);
      if (key.Length == 0) return;
      // Set transform
      AesManaged aes = new System.Security.Cryptography.AesManaged();
      AesManaged aes_decrypt = new AesManaged();

      aes.Key = key;
      aes.IV = iv;
      aes.Mode = System.Security.Cryptography.CipherMode.CBC;
      aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
      aes.BlockSize = 128;
      transform = aes.CreateEncryptor();

      aes_decrypt.Key = key;
      aes_decrypt.IV = iv;
      aes_decrypt.Mode = System.Security.Cryptography.CipherMode.CBC;
      aes_decrypt.Padding = System.Security.Cryptography.PaddingMode.None;
      aes_decrypt.BlockSize = 128;
      decryptTransform = aes_decrypt.CreateDecryptor();
    }

    private byte[] removeControlCharacters(byte[] plainbytes) {
      // Look for the DLE (Data Link Escape character, etc.)
      return plainbytes.TakeWhile(c => (c > 31 || c == 10 || c == 13)).ToArray();
    }

    public EncryptionProvider() {
      // Initialize and link native modules.
      CreateCrytoTransform();
    }
    
    public string Encrypt(string input, Encoding encoding) {
      byte[] cred = encoding.GetBytes(input);
      byte[] cipher = transform.TransformFinalBlock(cred, 0, cred.Length);
      return Convert.ToBase64String(cipher);
    }

    public string Decrypt(string input, Encoding encoding) {
      byte[] cipher = Convert.FromBase64String(input);
      byte[] plainbytes = decryptTransform.TransformFinalBlock(cipher, 0, cipher.Length);
      var newbytes = removeControlCharacters(plainbytes);
      return encoding.GetString(newbytes);
    }
  }
}
