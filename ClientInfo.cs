using System.Net;
using System.Security.Cryptography;

namespace ProtocolCryptographyC
{
    public class ClientInfo
    {
        public IPEndPoint ClientEndPoint { get; }
        public DateTime TimeConnection { get; }
        public DateTime TimeDisconnection { set;  get; }
        public byte[] Hash { get; set; }

        public ClientInfo(IPEndPoint clientEndPoint, DateTime timeConnection)
        {
            ClientEndPoint = clientEndPoint;
            TimeConnection = timeConnection;
        }
        public ClientInfo(IPEndPoint clientEndPoint, DateTime timeConnection, byte[] hash)
        {
            ClientEndPoint = clientEndPoint;
            TimeConnection = timeConnection;
            Hash = hash;
        }
    }
}
