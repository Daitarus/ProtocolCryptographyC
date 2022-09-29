using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ProtocolCryptographyC
{
    internal class MessageWork
    {
        public Socket socket;

        public MessageWork(Socket socket)
        {
            this.socket = socket;
        }

        public string SendMessage(byte[] message, Aes aes)
        {
            try
            {
                byte[]? bufferFile = Segment.PackSegment(TypeSegment.MESSAGE, (byte)0, EncryptAES(message, aes));
                socket.Send(bufferFile);
                return "I:Message was send";
            }
            catch (Exception e)
            {
                return $"F:{e}";
            }
        }

        public byte[] GetMessage(Aes aes)
        {
            try
            {
                Segment? segment = Segment.ParseSegment(socket);
                if (segment == null)
                {
                    return Encoding.UTF8.GetBytes("E:Wasn't get message");
                }
                if ((segment.Type != TypeSegment.MESSAGE) || (segment.Payload == null))
                {
                    return Encoding.UTF8.GetBytes("E:Wasn't get message");
                }
                segment.DecryptPayload(aes);
                return segment.Payload;
            }
            catch (Exception e)
            {
                return Encoding.UTF8.GetBytes($"F:{e}");
            }
        }

        private static byte[] EncryptAES(byte[] data, Aes aes)
        {
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (var ms = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        private static byte[] DecryptAES(byte[] data, Aes aes)
        {
            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (var ms = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
    }
}
