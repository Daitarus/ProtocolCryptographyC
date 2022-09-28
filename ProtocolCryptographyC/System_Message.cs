using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProtocolCryptographyC
{
    public enum System_Message : byte
    {
        GET_NOT_PCC = 0,
        NO_TRANSFER_AUTHORIZATION_INFO = 1,
        CONNECTED = 2,
        NOT_CONNECTED = 3,
        DISCONNECTED = 4,
        NOT_DISCONNECTED = 5,
        ERROR_START = 6,
        ERROR_ASK_GET_FILE = 7,
        NOT_FILE_INFO = 8,
        NOT_FOUND_ALLOWABLE_FILE = 9,
        FILE_WAS_NOT_TRANSFER = 10,
        FILE_WAS_TRANSFER = 11
    }
}
