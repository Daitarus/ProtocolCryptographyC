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

        public PccSystemMessage SendMessage(byte[] message)
        {
            if(message == null)
                throw new ArgumentNullException(nameof(message));
            try
            {
                byte[]? bufferFile = Segment.PackSegment(TypeSegment.MESSAGE, 0, cryptAES.Encrypt(message));
                socket.Send(bufferFile);
                return new PccSystemMessage(PccSystemMessageKey.INFO, "Message was sent");
            }
            catch (Exception e)
            {
                return new PccSystemMessage(PccSystemMessageKey.FATAL_ERROR, e.Message, e.StackTrace);
            }
        }

        public PccSystemMessage GetMessage(out byte[]? message)
        {
            message = null;
            try
            {
                Segment? segment = Segment.ParseSegment(socket);
                if ((segment == null) || (segment.Type != TypeSegment.MESSAGE) || (segment.Payload == null))
                {
                    return new PccSystemMessage(PccSystemMessageKey.ERROR, "Message wasn't got");
                }
                message = cryptAES.Decrypt(segment.Payload);
                return new PccSystemMessage(PccSystemMessageKey.INFO, "Message was got");
            }
            catch (CryptographicException e)
            {
                return new PccSystemMessage(PccSystemMessageKey.FATAL_ERROR, e.Message, e.StackTrace);
            }
        }
    }
}
