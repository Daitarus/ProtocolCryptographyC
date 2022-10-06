using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CryptL;

namespace ProtocolCryptographyC
{
    public class FileTransport
    {
        public Socket socket;
        private CryptAES cryptAES;
        
        public FileTransport(Socket socket, CryptAES cryptAES)
        {
            this.socket = socket;
            this.cryptAES = cryptAES;
        }


        public string SendFileInfo(string fileName)
        {
            try
            {
                //encrypt fileInfo + ask get file
                byte[]? bufferFile = Segment.PackSegment(TypeSegment.ASK_GET_FILE, 0, cryptAES.Encrypt(Encoding.UTF8.GetBytes(fileName)));
                socket.Send(bufferFile);
                return "I:File info was sent";
            }
            catch (Exception e)
            {
                return $"F:{e}";
            }
        }

        public string GetFileInfo()
        {
            try
            {
                //wait ask get file + decrypt fileInfo
                Segment? segment = Segment.ParseSegment(socket);
                if (segment == null)
                {
                    return "E:File info wasn't got";
                }
                if ((segment.Type != TypeSegment.ASK_GET_FILE) || (segment.Payload == null))
                {
                    return "E:File info wasn't got";
                }       
                return Encoding.UTF8.GetString(cryptAES.Decrypt(segment.Payload));
            }
            catch (Exception e)
            {
                return $"F:{e}";
            }
        }

        public string SendFile(string fileName)
        {
            if(fileName==null)
                throw new ArgumentNullException(nameof(fileName));

            try
            {
                byte[]? bufferFile = null;
                byte[]? buffer = null;

                //check file and send aes(system message)
                FileInfo fileInfo = new FileInfo(fileName);
                buffer = Segment.PackSegment(TypeSegment.FILE, 0, cryptAES.Encrypt(Encoding.UTF8.GetBytes("error")));
                if (!fileInfo.Exists)
                {
                    socket.Send(buffer);
                    return $"W:File not found - File:\"{fileInfo.FullName}\"";
                }
                long numAllBlock = (long)Math.Ceiling((double)fileInfo.Length / (double)Segment.lengthBlockFile);
                if ((fileInfo.Length == 0) || (numAllBlock >= 256))
                {
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
                buffer = Segment.PackSegment(TypeSegment.FILE, 0, cryptAES.Encrypt(bufferFile));
                if (buffer == null)
                {
                    return $"E:File info wasn't sent - File:\"{fileInfo.FullName}\"";
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
                        buffer = Segment.PackSegment(TypeSegment.FILE, (byte)i, cryptAES.Encrypt(bufferFile));
                        if (buffer == null)
                        {
                            return $"E:File block {i}/{numAllBlock} wasn't sent - File:\"{fileInfo.FullName}\"";
                        }
                        socket.Send(buffer);
                    }
                }
                return $"I:All file's block [{numAllBlock}] was sent - File:\"{fileInfo.FullName}\"";
            }
            catch(Exception e)
            {
                return $"F:{e}";
            }
        }
        public string GetFile(string path)
        {
            try
            {
                //get first part file aes(system message or number of block + fileInfo)
                Segment? segment;
                segment = Segment.ParseSegment(socket);
                
                if (segment == null)
                {
                    return "E:File info wasn't got";
                }
                if ((segment.Type != TypeSegment.FILE) || (segment.Payload == null))
                {
                    return "E:File info wasn't got";
                }
                byte[] buffer = cryptAES.Decrypt(segment.Payload);
                if (Encoding.UTF8.GetString(buffer) == "error")
                {
                    return $"W:File not found or very big";
                }

                byte numAllBlock = buffer[0];
                byte[] bufferFile = new byte[buffer.Length - 1];
                for (int i = 1; i < buffer.Length; i++)
                {
                    bufferFile[i - 1] = buffer[i];
                }

                //create directory
                if(path==null)
                {
                    path = "";
                }
                if(path!="")
                {
                    if(!Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path);
                    }
                }

                //get file
                FileInfo fileInfo = new FileInfo(path + Encoding.UTF8.GetString(bufferFile));
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
                        fstream.Seek(i * Segment.lengthBlockFile, SeekOrigin.Begin);
                        fstream.Write(cryptAES.Decrypt(segment.Payload));
                    }
                }
                return $"I:All file's block [{numAllBlock}] was get - File:\"{fileInfo.Name}\"";
            }
            catch(Exception e)
            {
                return $"F:{e}";
            }
        }
    }
}
