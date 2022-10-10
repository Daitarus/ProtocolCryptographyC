using CryptL;
using System.Net;
using System.Net.Sockets;

namespace ProtocolCryptographyC
{
    public sealed class PccServer
    {
        public delegate bool Authorization(byte[] hash);
        public delegate void MainServerAlgorithm(MessageTransport messageTransport, FileTransport fileTransport, ClientInfo clientInfo);
        public delegate void GetSystemMessage(PccSystemMessage systemMessage);

        private CryptRSA cryptRSA;
        private IPEndPoint serverEndPoint;
        private Socket listenSocket;


        public PccServer(IPEndPoint serverEndPoint, CryptRSA cryptRSA)
        {
            this.serverEndPoint = serverEndPoint;
            this.cryptRSA = cryptRSA;
        }
        public PccSystemMessage Start(Authorization authorization, MainServerAlgorithm algorithm, GetSystemMessage getSystemMessage)
        {
            try
			{
                while (true)
				{
					listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
					listenSocket.Bind(serverEndPoint);
					listenSocket.Listen(1);
                    Socket clientSocket = listenSocket.Accept();
                    Thread clientWork = new Thread(() => ClientWork(clientSocket, authorization, algorithm, getSystemMessage));
                    clientWork.Start();
					listenSocket.Close();
				}
			}
			catch(Exception e)
			{
                return new PccSystemMessage(PccSystemMessageKey.FATAL_ERROR, e.Message, e.StackTrace);
            }
		}

        public void ClientWork(Socket socket, Authorization authorization, MainServerAlgorithm mainServerAlgorithm, GetSystemMessage getSystemMessage)
        {
            ClientInfo clientInfo = new ClientInfo((IPEndPoint)socket.RemoteEndPoint, DateTime.Now);
            CryptAES cryptAES = new CryptAES();

            PccSystemMessage systemMessage = new PccSystemMessage(PccSystemMessageKey.INFO, "connected", $"{clientInfo.ClientEndPoint.Address}:{clientInfo.ClientEndPoint.Port}");
            getSystemMessage(systemMessage);

            try
            {
                //wait first message
                Segment segment = Segment.ParseSegment(socket);
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
                                    systemMessage.Update(PccSystemMessageKey.INFO, "authorization");
                                    getSystemMessage(systemMessage);

                                    buffer = Segment.PackSegment(TypeSegment.ANSWER_AUTHORIZATION_YES, 0, null);
                                    socket.Send(buffer);

                                    //mainServerAlgorithm execution
                                    mainServerAlgorithm(new MessageTransport(socket, cryptAES), new FileTransport(socket, cryptAES, clientInfo.ClientEndPoint.Port), clientInfo);
                                }
                                else
                                {
                                    systemMessage.Update(PccSystemMessageKey.WARRNING, "no authorization");
                                    getSystemMessage(systemMessage);

                                    buffer = Segment.PackSegment(TypeSegment.ANSWER_AUTHORIZATION_NO, 0, null);
                                    socket.Send(buffer);
                                }
                            }
                        }
                    }
                }

            }
            catch (Exception e)
            {
                systemMessage.Update(PccSystemMessageKey.FATAL_ERROR, e.Message, e.StackTrace);
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
