using System;
using System.Text;
using System.IO;

namespace wintools.Test {

  class Tester {
    public static void Encryption(EncryptionProvider provider) {
      var cipher_s = provider.Encrypt("192.168.1.22 2323 foo bar", Encoding.ASCII);

      File.WriteAllText("credwin.txt", cipher_s + "\n", Encoding.ASCII);

      string read_s = File.ReadAllText("credwin.txt", Encoding.ASCII);

      string plaintext = provider.Decrypt(read_s, Encoding.ASCII);

      Console.WriteLine(plaintext);
    }
  }

  class Start {
    static void Main(string[] args) {
      var provider = new EncryptionProvider(wintools.Test.Properties.Settings.Default.privateKey, wintools.Test.Properties.Settings.Default.sharedSecret);

      Tester.Encryption(provider);
      InternalTest.EncryptionFromFile(provider);
    }
  }
}
