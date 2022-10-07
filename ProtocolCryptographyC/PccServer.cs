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
        public delegate void GetSystemMessage(PccSystemMessage systemMessage);

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
        public PccSystemMessage Start(Authorization authorization, Algorithm algorithm, GetSystemMessage getSystemMessage)
        {
            try
			{
				while (true)
				{
					listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
					listenSocket.Bind(serverEndPoint);
					listenSocket.Listen(1);
                    Socket clientSocket = listenSocket.Accept();
                    Task clientWork = new Task(() => ClientWork(clientSocket, authorization, algorithm, getSystemMessage));
                    clientWork.Start();
					listenSocket.Close();
				}
			}
			catch(Exception e)
			{
                return new PccSystemMessage(PccSystemMessageKey.FATAL_ERROR, e.Message, e.StackTrace);
            }
		}
		private void ClientWork(Socket socket, Authorization authorization, Algorithm algorithm, GetSystemMessage getSystemMessage)
        {
            ClientInfo clientInfo = new ClientInfo((IPEndPoint)socket.RemoteEndPoint, DateTime.Now);

            PccSystemMessage systemMessage = new PccSystemMessage(PccSystemMessageKey.INFO, "connected", $"{clientInfo.ClientEndPoint.Address}:{clientInfo.ClientEndPoint.Port}");
            getSystemMessage(systemMessage);

            Segment segment = new Segment();           
            CryptAES cryptAES = new CryptAES();

            try
            {
                //wait first message
                segment = Segment.ParseSegment(socket);
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
                        segment = Segment.ParseSegment(socket);
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
                                    systemMessage.Message = "authorization";
                                    getSystemMessage(systemMessage);

                                    buffer = Segment.PackSegment(TypeSegment.ANSWER_AUTHORIZATION_YES, 0, null);
                                    socket.Send(buffer);

                                    //algorithm execution
                                    messageTransport = new MessageTransport(socket, cryptAES);
                                    fileTransport = new FileTransport(socket, cryptAES);
                                    algorithm(clientInfo);
                                }
                                else
                                {
                                    systemMessage.Key = PccSystemMessageKey.WARRNING;
                                    systemMessage.Message = "no authorization";
                                    getSystemMessage(systemMessage);

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
                systemMessage.Key = PccSystemMessageKey.FATAL_ERROR;
                systemMessage.Message = e.Message;
                systemMessage.AdditionalMessage = e.StackTrace;
                getSystemMessage(systemMessage);
            }
            finally
            {
                getSystemMessage(Disconnect(socket, clientInfo));
            }
        }

        private PccSystemMessage Disconnect(Socket socket, ClientInfo clientInfo)
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
            return new PccSystemMessage(PccSystemMessageKey.INFO, "Disconnect");
        }  
    }
}
