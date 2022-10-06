using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CryptL;

namespace ProtocolCryptographyC
{
    public class MessageTransport
    {
        public Socket socket;
        private CryptAES cryptAES;

        public MessageTransport(Socket socket, CryptAES cryptAES)
        {
            this.socket = socket;
            this.cryptAES = cryptAES;
        }

        public string SendMessage(byte[] message)
        {
            if(message == null)
                throw new ArgumentNullException(nameof(message));
            try
            {
                byte[]? bufferFile = Segment.PackSegment(TypeSegment.MESSAGE, 0, cryptAES.Encrypt(message));
                socket.Send(bufferFile);
                return "I:Message was sent";
            }
            catch (Exception e)
            {
                return $"F:{e}";
            }
        }

        public byte[] GetMessage()
        {
            try
            {
                Segment? segment = Segment.ParseSegment(socket);
                if ((segment == null) || (segment.Type != TypeSegment.MESSAGE) || (segment.Payload == null))
                {
                    return Encoding.UTF8.GetBytes("E:Message wasn't got");
                }
                return cryptAES.Decrypt(segment.Payload);
            }
            catch (Exception e)
            {
                return Encoding.UTF8.GetBytes($"F:{e}");
            }
        }
    }
}
