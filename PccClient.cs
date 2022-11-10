using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CryptL;

namespace ProtocolCryptographyC
{
    public sealed class PccClient
    {
        private IPEndPoint serverEndPoint;
        private Socket socket;
        private byte[] hash;
        private CryptAES cryptAES;
        public FileTransport fileTransport;
        public MessageTransport messageTransport;

        public PccClient(IPEndPoint serverEndPoint, string authorizationString)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            this.serverEndPoint = serverEndPoint;
            hash = HashSHA256.GetHash(Encoding.UTF8.GetBytes(authorizationString));
            cryptAES = new CryptAES();
        }
        public PccSystemMessage Connect()
        {
            try
            {
                //tcp connect
                socket.Connect(serverEndPoint);

                //ask get publicKeyRSA
                byte[]? buffer = Segment.PackSegment(TypeSegment.ASK_GET_PKEY, 0, null);
                socket.Send(buffer);

                //waiting answer publicKeyRSA
                Segment? segment = Segment.ParseSegment(socket);
                if((segment == null) || (segment.Type != TypeSegment.PKEY) || (segment.Payload == null))
                {
                    return new PccSystemMessage(PccSystemMessageKey.ERROR, "Public key RSA wasn't got");
                }
                CryptRSA cryptRSA = new CryptRSA(segment.Payload, false);

                //send hash + aesKey
                int length = hash.Length + cryptAES.Key.Length + cryptAES.IV.Length;
                buffer = new byte[length];
                Array.Copy(hash, 0, buffer, 0, hash.Length);
                Array.Copy(cryptAES.Key, 0, buffer, hash.Length, cryptAES.Key.Length);
                Array.Copy(cryptAES.IV, 0, buffer, hash.Length + cryptAES.Key.Length, cryptAES.IV.Length);

                buffer = cryptRSA.Encrypt(buffer);
                buffer = Segment.PackSegment(TypeSegment.AUTHORIZATION, 0, buffer);
                if (buffer == null)
                {
                    return new PccSystemMessage(PccSystemMessageKey.ERROR, "Authorization info wasn't sent");
                }
                socket.Send(buffer);

                //wait answer authorization
                segment = Segment.ParseSegment(socket);
                if(segment == null || segment.Type != TypeSegment.ANSWER_AUTHORIZATION_YES)
                {
                    return new PccSystemMessage(PccSystemMessageKey.ERROR, "No authorization");
                }

                //connect
                messageTransport = new MessageTransport(socket, cryptAES);
                fileTransport = new FileTransport(socket, cryptAES, 0);
                return new PccSystemMessage(PccSystemMessageKey.INFO, "Successful connect");
            }
            catch(Exception e)
            {
                return new PccSystemMessage(PccSystemMessageKey.FATAL_ERROR, e.Message, e.StackTrace);
            }
        }

        public PccSystemMessage Disconnect()
        {
            try
            {
                socket.Shutdown(SocketShutdown.Both);
            }
            finally
            {
                socket.Close();               
            }
            return new PccSystemMessage(PccSystemMessageKey.INFO, "Disconnect");
        }
    }
}