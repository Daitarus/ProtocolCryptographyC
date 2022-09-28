using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ProtocolCryptographyC
{
    public class ClientInfo
    {
        public string Ip { get; }
        public string Port { get; }
        public Aes aes { get; }
        public DateTime TimeConnection { get; }
        public DateTime TimeDisconnection { set;  get; }
        public byte[] Hash { get; }

        public ClientInfo(string ip, string port, Aes aes, DateTime timeConnection, byte[] hash)
        {
            Ip = ip;
            Port = port;
            this.aes = aes;
            TimeConnection = timeConnection;
            Hash = hash;
        }
    }
}
