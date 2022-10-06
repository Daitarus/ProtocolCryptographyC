using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using CryptL;

namespace ProtocolCryptographyC
{
    public sealed class PccServer
    {
        public delegate bool Authorization(byte[] hash);
        public delegate void Algorithm(ClientInfo clientInfo);
        public delegate void GetSystemMessage(string systemMessage);
        private CryptRSA cryptRSA;
        private IPEndPoint serverEndPoint;
        private Socket listenSocket  = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        public FileTransport fileTransport;
        public MessageTransport messageTransport;


        public PccServer(IPEndPoint serverEndPoint, CryptRSA cryptRSA)
        {
            this.serverEndPoint = serverEndPoint;
            this.cryptRSA = cryptRSA;
        }
        public string Start(Authorization authorization, Algorithm algorithm, GetSystemMessage getSystemMessage)
        {
            try
			{
				while (true)
				{
					listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
					listenSocket.Bind(serverEndPoint);
					listenSocket.Listen(1);
					ClientWork(listenSocket.Accept(), authorization, algorithm, getSystemMessage);
					listenSocket.Close();
				}
			}
			catch(Exception e)
			{
				return $"F:{e}";
			}
		}
		private async void ClientWork(Socket socket, Authorization authorization, Algorithm algorithm, GetSystemMessage getSystemMessage)
        {
            ClientInfo clientInfo = new ClientInfo((IPEndPoint)socket.RemoteEndPoint, DateTime.Now);
            string system_message_base = $"I:{clientInfo.ClientEndPoint.Address}:{clientInfo.ClientEndPoint.Port} - ";
            getSystemMessage(system_message_base + "connected");
            Segment segment = new Segment();           
            CryptAES cryptAES = new CryptAES();

            try
            {
                //wait first message
                await Task.Run(() => segment = Segment.ParseSegment(socket));
                if (segment != null)
                {
                    if (segment.Type == TypeSegment.ASK_GET_PKEY)
                    {
                        //send publicKeyRSA
                        byte[]? buffer = Segment.PackSegment(TypeSegment.PKEY, 0, cryptRSA.PublicKey);
                        if (buffer != null)
                        {
                            socket.Send(buffer);
                        }

                        //wait RSA(hash+aesKey)
                        await Task.Run(() => segment = Segment.ParseSegment(socket));
                        if (segment != null)
                        {
                            if ((segment.Type == TypeSegment.AUTHORIZATION) && (segment.Payload != null))
                            {
                                //decrypt RSA
                                buffer = cryptRSA.Decrypt(segment.Payload);
                                byte[] hash = new byte[HashSHA256.Length];
                                byte[] aesKey = new byte[cryptAES.Key.Length];
                                byte[] aesIv = new byte[cryptAES.IV.Length];
                                Array.Copy(buffer, 0, hash, 0, hash.Length);
                                Array.Copy(buffer, hash.Length, aesKey, 0, aesKey.Length);
                                Array.Copy(buffer, hash.Length + aesKey.Length, aesIv, 0, aesIv.Length);
                                clientInfo.Hash = hash;
                                cryptAES = new CryptAES(aesKey, aesIv);

                                //authorization
                                if (authorization(hash))
                                {
                                    getSystemMessage(system_message_base + "authorization");
                                    buffer = Segment.PackSegment(TypeSegment.ANSWER_AUTHORIZATION_YES, 0, null);
                                    socket.Send(buffer);

                                    //algorithm execution
                                    messageTransport = new MessageTransport(socket, cryptAES);
                                    fileTransport = new FileTransport(socket, cryptAES);
                                    algorithm(clientInfo);
                                }
                                else
                                {
                                    getSystemMessage(system_message_base + "no authorization");
                                    buffer = Segment.PackSegment(TypeSegment.ANSWER_AUTHORIZATION_NO, 0, null);
                                    socket.Send(buffer);
                                }
                            }
                        }
                    }
                }
            }
            catch(Exception e)
            {
                getSystemMessage($"F:{e}");
            }
            finally
            {
                Disconnect(socket, clientInfo);
                getSystemMessage(system_message_base + "disconnect");
            }
        }

        private void Disconnect(Socket socket, ClientInfo clientInfo)
        {
            try
            {
                clientInfo.TimeDisconnection = DateTime.Now;
                socket.Shutdown(SocketShutdown.Both);
            }
            finally
            {
                socket.Close();
            }
        }  
    }
}
