using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ProtocolCryptographyC
{
    internal class FileWork
    {
        public Socket socket;
        
        public FileWork(Socket socket)
        {
            this.socket = socket;
        }


        public string SendFileInfo(string fileName, Aes aes)
        {
            try
            {
                //encrypt fileInfo + ask get file
                byte[]? bufferFile = Segment.PackSegment(TypeSegment.ASK_GET_FILE, (byte)0, EncryptAES(Encoding.UTF8.GetBytes(fileName), aes));
                socket.Send(bufferFile);
                return "I:File info was send";
            }
            catch (Exception e)
            {
                return $"F:{e}";
            }
        }

        public string GetFileInfo(Aes aes)
        {
            try
            {
                //wait ask get file + decrypt fileInfo
                Segment? segment = Segment.ParseSegment(socket);
                if (segment == null)
                {
                    return "E:Wasn't get file info";
                }
                if ((segment.Type != TypeSegment.ASK_GET_FILE) || (segment.Payload == null))
                {
                    return "E:Wasn't get file info";
                }
                segment.DecryptPayload(aes);           
                return Encoding.UTF8.GetString(segment.Payload);
            }
            catch (Exception e)
            {
                return $"F:{e}";
            }
        }

        public string SendFile(string fileName, Aes aes)
        {
            try
            {
                byte[]? bufferFile = null;
                byte[]? buffer = null;

                //check file and send aes(system message)
                if(fileName==null)
                {
                    buffer = Segment.PackSegment(TypeSegment.FILE, (byte)0, EncryptAES(Encoding.UTF8.GetBytes("error"), aes));
                    socket.Send(buffer);
                    return $"W:File not found - File:\"{fileName}\"";
                }
                FileInfo fileInfo = new FileInfo(fileName);
                if (!fileInfo.Exists)
                {
                    buffer = Segment.PackSegment(TypeSegment.FILE, (byte)0, EncryptAES(Encoding.UTF8.GetBytes("error"),aes));
                    socket.Send(buffer);
                    return $"W:File not found - File:\"{fileInfo.FullName}\"";
                }
                long numAllBlock = (long)Math.Ceiling((double)fileInfo.Length / (double)Segment.lengthBlockFile);
                if ((fileInfo.Length == 0) || (numAllBlock >= 256))
                {
                    buffer = Segment.PackSegment(TypeSegment.FILE, (byte)0, EncryptAES(Encoding.UTF8.GetBytes("error"), aes));
                    socket.Send(buffer);
                    return $"W:File is very big - File:\"{fileInfo.FullName}\"";
                }
                //send first file part aes(system message or number of block + fileInfo)
                buffer = Encoding.UTF8.GetBytes(fileInfo.Name);
                bufferFile = new byte[buffer.Length + 1];
                bufferFile[0] = (byte)numAllBlock;
                for (int i = 0; i < buffer.Length; i++)
                {
                    bufferFile[i + 1] = buffer[i];
                }
                buffer = Segment.PackSegment(TypeSegment.FILE, (byte)0, EncryptAES(bufferFile, aes));
                if (buffer == null)
                {
                    return $"E:Wasn't send file info - File:\"{fileInfo.FullName}\"";
                }
                socket.Send(buffer);

                //send file
                using (FileStream fstream = File.Open(fileInfo.FullName, FileMode.Open))
                {
                    //load file part
                    int numReadByte;
                    for (int i = 0; i < numAllBlock; i++)
                    {
                        buffer = new byte[Segment.lengthBlockFile];
                        fstream.Seek(i * Segment.lengthBlockFile, SeekOrigin.Begin);
                        numReadByte = fstream.Read(buffer);
                        bufferFile = new byte[numReadByte];
                        for (int j = 0; j < numReadByte; j++)
                        {
                            bufferFile[j] = buffer[j];
                        }

                        //send part file
                        buffer = Segment.PackSegment(TypeSegment.FILE, (byte)i, EncryptAES(bufferFile, aes));
                        if (buffer == null)
                        {
                            return $"E:Wasn't send file block {i}/{numAllBlock} - File:\"{fileInfo.FullName}\"";
                        }
                        socket.Send(buffer);
                    }
                }
                return $"I:All file's block [{numAllBlock}] was send - File:\"{fileInfo.FullName}\"";
            }
            catch(Exception e)
            {
                return $"F:{e}";
            }
        }
        public string GetFile(string path, Aes aes)
        {
            try
            {
                //get first part file aes(system message or number of block + fileInfo)
                Segment? segment;
                segment = Segment.ParseSegment(socket);
                
                if (segment == null)
                {
                    return "E:Wasn't get file info";
                }
                if ((segment.Type != TypeSegment.FILE) || (segment.Payload == null))
                {
                    return "E:Wasn't get file info";
                }
                segment.DecryptPayload(aes);
                if (Encoding.UTF8.GetString(segment.Payload) == "error")
                {
                    return $"W:File not found or very big";
                }

                byte numAllBlock = segment.Payload[0];
                byte[] buffer = new byte[segment.Payload.Length - 1];
                for (int i = 1; i < segment.Payload.Length; i++)
                {
                    buffer[i - 1] = segment.Payload[i];
                }
                if(path==null)
                {
                    path = "";
                }

                //create directory
                if(path!="")
                {
                    if(!Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path);
                    }
                }

                FileInfo fileInfo = new FileInfo(path + Encoding.UTF8.GetString(buffer));

                //get file
                using (FileStream fstream = new FileStream(fileInfo.FullName, FileMode.OpenOrCreate))
                {
                    for (int i = 0; i < numAllBlock; i++)
                    {
                        segment = Segment.ParseSegment(socket);
                        if (segment == null)
                        {
                            return $"E:Wasn't get file block {i}/{numAllBlock} - File:\"{fileInfo.Name}\"";
                        }
                        if ((segment.Type != TypeSegment.FILE) || (segment.Payload == null))
                        {
                            return $"E:Wasn't get file block {i}/{numAllBlock} - File:\"{fileInfo.Name}\"";
                        }
                        segment.DecryptPayload(aes);
                        fstream.Seek(i * Segment.lengthBlockFile, SeekOrigin.Begin);
                        fstream.Write(segment.Payload);
                    }
                }
                return $"I:All file's block [{numAllBlock}] was get - File:\"{fileInfo.Name}\"";
            }
            catch(Exception e)
            {
                return $"F:{e}";
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

        public static byte[] DecryptAES(byte[] data, Aes aes)
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
