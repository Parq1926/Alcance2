using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography;
using System.IO;
using System.Text;

/// <summary>
/// Clase para encriptar/desencriptar datos
/// </summary>
public static class Encriptacion
{
    private static readonly string clave = "Pame.1998"; // 16 caracteres

    public static string Encriptar(string texto)
    {
        try
        {
            byte[] iv = new byte[16];
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(clave.PadRight(32).Substring(0, 32));
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(texto);
                        }
                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }
        catch
        {
            return texto;
        }
    }

    public static string Desencriptar(string textoEncriptado)
    {
        try
        {
            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(textoEncriptado);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(clave.PadRight(32).Substring(0, 32));
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }
        catch
        {
            return textoEncriptado;
        }
    }
}