using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Xml.Linq;

namespace wintools.Test {
  class InternalTest {
    public static void EncryptionFromFile(EncryptionProvider provider) {
      string plainfile = "resources\\security-plain.xml";
      string encryptedfile = "resources\\security-enc.xml";
      string decryptedfile = "resources\\security-restored.txt";
      if (System.Environment.OSVersion.Platform == PlatformID.Unix) {
        plainfile = plainfile.Replace("\\", "/");
        encryptedfile = encryptedfile.Replace("\\", "/");
        decryptedfile = decryptedfile.Replace("\\", "/");
      }

      var credstring = File.ReadAllText(plainfile, Encoding.UTF8);
      var cipher_s = provider.Encrypt(credstring, Encoding.UTF8);
      File.WriteAllText(encryptedfile, cipher_s, Encoding.UTF8);

      string read_s = File.ReadAllText(encryptedfile, Encoding.UTF8);
      string plaintext = provider.Decrypt(read_s, Encoding.UTF8);

      Console.WriteLine(plaintext);
      File.WriteAllText(decryptedfile, plaintext + "\n", Encoding.UTF8);

      var doc = XDocument.Parse(plaintext);
      string module = "Click", store = "GRANTS", environment = "STAGING";

      var el = doc.Descendants("Module").FirstOrDefault(e => e.Attribute("name").Value == module).Descendants("Store").FirstOrDefault(e => e.Attribute("name").Value == store).Descendants("Credential").FirstOrDefault(e => e.Attribute("environment").Value == environment);
      var username = el.Attribute("username").Value;
      var password = el.Attribute("password").Value;

      module = "Epic";
      el = doc.Descendants("Module").FirstOrDefault(e => e.Attribute("name").Value == module).Descendants("Credential").FirstOrDefault(e => e.Attribute("environment").Value == environment);
      username = el.Attribute("username").Value;
      password = el.Attribute("password").Value;

      module = "OnBase";
      el = doc.Descendants("Module").FirstOrDefault(e => e.Attribute("name").Value == module).Descendants("Credential").FirstOrDefault(e => e.Attribute("environment").Value == environment);
      username = el.Attribute("username").Value;
      password = el.Attribute("password").Value;
    }
  }
}
