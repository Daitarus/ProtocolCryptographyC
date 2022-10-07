namespace ProtocolCryptographyC
{
    public class PccSystemMessage
    {
        public PccSystemMessageKey Key { get; set; }
        public string Message { get; set; }
        public string? AdditionalMessage { get; set; }

        public PccSystemMessage(PccSystemMessageKey key, string message)
        {
            Key = key;
            Message = message;
        }
        public PccSystemMessage(PccSystemMessageKey key, string message, string additionalMessage)
        {
            Key = key;
            Message = message;
            AdditionalMessage = additionalMessage;
        }
    }
}
