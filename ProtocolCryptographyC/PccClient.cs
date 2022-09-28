using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace ProtocolCryptographyC
{
    public sealed class PccClient
    {
        private IPEndPoint serverEndPoint;
        private Socket socket;
        private byte[] hash;
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        private Aes aes;
        private FileWork fileWork;

        public PccClient(IPEndPoint serverEndPoint, string authorizationString)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            this.serverEndPoint = serverEndPoint;
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(authorizationString));
            }
            aes = Aes.Create();
        }
        public string Connect()
        {
            try
            {
                //tcp connect
                socket.Connect(serverEndPoint);

                //ask get publicKeyRSA
                byte[]? buffer = Segment.PackSegment(TypeSegment.ASK_GET_PKEY, (byte)0, null);
                socket.Send(buffer);

                //waiting answer publicKeyRSA
                Segment? segment = Segment.ParseSegment(socket);
                if(segment == null)
                {
                    return "E:Public key RSA wasn't get";
                }
                if((segment.Type != TypeSegment.PKEY) || (segment.Payload == null))
                {
                    return "E:Public key RSA wasn't get";
                }
                RSAParameters publicKey = rsa.ExportParameters(false);
                publicKey.Modulus = segment.Payload;
                rsa.ImportParameters(publicKey);

                //send hash + aesKey
                int length = hash.Length + aes.Key.Length + aes.IV.Length;
                buffer = new byte[length];
                for (int i = 0; i < hash.Length; i++) 
                {
                    buffer[i] = hash[i];
                }
                for (int i = 0; i < aes.Key.Length; i++) 
                {
                    buffer[hash.Length + i] = aes.Key[i];
                }
                for (int i = 0; i < aes.IV.Length; i++)
                {
                    buffer[hash.Length + aes.Key.Length + i] = aes.IV[i];
                }

                buffer = rsa.Encrypt(buffer, false);
                buffer = Segment.PackSegment(TypeSegment.AUTHORIZATION, (byte)0, buffer);
                if (buffer == null)
                {
                    return "E:Wasn't send authorization info";
                }
                socket.Send(buffer);

                //wait answer authorization
                segment = Segment.ParseSegment(socket);
                if(segment == null)
                {
                    return "E:No authorization";
                }
                if(segment.Type != TypeSegment.ANSWER_AUTHORIZATION_YES)
                {
                    return "E:No authorization";
                }

                //connect
                fileWork = new FileWork(socket);
                return "I:Successful connect";
            }
            catch(Exception e)
            {
                return $"F:{e}";
            }
        }
        public string TransferFile()
        {
            return fileWork.TransferFile(aes);
        }
        public string GetFile(FileInfo fileInfo)
        {
            return fileWork.GetFile(fileInfo, aes);
        }
        public string Disconnect()
        {
            try
            {
                socket.Shutdown(SocketShutdown.Both);
            }
            finally
            {
                socket.Close();
            }
            return "I:Disconnect";
        }
    }
}