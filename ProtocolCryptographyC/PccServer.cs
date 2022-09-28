using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ProtocolCryptographyC
{
    public sealed class PccServer
    {
        public delegate bool Authorization(byte[] hash);
        public delegate void Algorithm(ClientInfo clientInfo);
        public delegate void GetSystemMessage(string systemMessage);

        private IPEndPoint serverEndPoint;
        private Socket listenSocket  = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        RSACryptoServiceProvider rsa;
        private FileWork fileWork;


        public PccServer(IPEndPoint serverEndPoint, RSACryptoServiceProvider rsa)
        {
            this.serverEndPoint = serverEndPoint;
            this.rsa = rsa;
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
            getSystemMessage($"I:Client({((IPEndPoint)(socket.RemoteEndPoint)).Address.ToString()}:{((IPEndPoint)(socket.RemoteEndPoint)).Port.ToString()}) - connected");
            Segment segment = new Segment();
            byte[] hash = new byte[20];
            Aes aes = Aes.Create();

            try
            {
                //wait first message
                await Task.Run(() => segment = Segment.ParseSegment(socket));
                if (segment != null)
                {
                    if (segment.Type == TypeSegment.ASK_GET_PKEY)
                    {
                        //send publicKeyRSA
                        byte[] publicKeyRSA = rsa.ExportParameters(false).Modulus;
                        byte[]? buffer = Segment.PackSegment(TypeSegment.PKEY, (byte)0, publicKeyRSA);
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
                                buffer = rsa.Decrypt(segment.Payload, false);
                                byte[] aesKey = new byte[aes.Key.Length];
                                byte[] aesIv = new byte[aes.IV.Length];
                                for (int i = 0; i < hash.Length; i++) 
                                {
                                    hash[i] = buffer[i];
                                }
                                for(int i = 0; i < aes.Key.Length; i++)
                                {
                                    aesKey[i] = buffer[hash.Length + i];
                                }
                                for (int i = 0; i < aes.IV.Length; i++) 
                                {
                                    aesIv[i] = buffer[hash.Length + aes.Key.Length + i];
                                }
                                aes.Key = aesKey;
                                aes.IV = aesIv;

                                //authorization
                                if (authorization(hash))
                                {
                                    getSystemMessage($"I:Client({((IPEndPoint)(socket.RemoteEndPoint)).Address.ToString()}:{((IPEndPoint)(socket.RemoteEndPoint)).Port.ToString()}) - authorization");
                                    buffer = Segment.PackSegment(TypeSegment.ANSWER_AUTHORIZATION_YES, (byte)0, null);
                                    socket.Send(buffer);
                                    //algorithm execution
                                    fileWork = new FileWork(socket);
                                    algorithm(new ClientInfo(((IPEndPoint)(socket.RemoteEndPoint)).Address.ToString(), ((IPEndPoint)(socket.RemoteEndPoint)).Port.ToString(), aes, DateTime.Now));
                                }
                                else
                                {
                                    getSystemMessage($"I:Client({((IPEndPoint)(socket.RemoteEndPoint)).Address.ToString()}:{((IPEndPoint)(socket.RemoteEndPoint)).Port.ToString()}) - no authorization");
                                    buffer = Segment.PackSegment(TypeSegment.ANSWER_AUTHORIZATION_NO, (byte)0, null);
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
                getSystemMessage(Disconnect(socket));
            }
        }

        public string TransferFile(Aes aes)
        {
            return fileWork.TransferFile(aes);
        }
        public string GetFile(FileInfo fileInfo, Aes aes)
        {
            return fileWork.GetFile(fileInfo, aes);
        }

        private string Disconnect(Socket socket)
        {
            string SystemMessage = "I:disconnect";
            try
            {
                SystemMessage = $"I:Client({((IPEndPoint)(socket.RemoteEndPoint)).Address.ToString()}:{((IPEndPoint)(socket.RemoteEndPoint)).Port.ToString()}) - disconnect";
                socket.Shutdown(SocketShutdown.Both);
            }
            finally
            {
                socket.Close();
            }
            return SystemMessage;
        }  
    }
}
