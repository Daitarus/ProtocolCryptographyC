namespace ProtocolCryptographyC
{
    public class PccSystemMessage
    {
        private PccSystemMessageKey key;
        private string message;
        private string additionalMessage;

        public PccSystemMessageKey Key { get { return key; } }
        public string Message { get { return message; } }
        public string AdditionalMessage { get { return additionalMessage; } }

        public PccSystemMessage(PccSystemMessageKey key, string message)
        {
            this.key = key;
            this.message = message;
        }
        public PccSystemMessage(PccSystemMessageKey key, string message, string additionalMessage)
        {
            this.key = key;
            this.message = message;
            this.additionalMessage = additionalMessage;
        }
        public void Update(PccSystemMessageKey key, string message)
        {
            this.key = key;
            this.message = message;
        }
        public void Update(PccSystemMessageKey key, string message, string additionalMessage)
        {
            Update(key, message);
            this.additionalMessage = additionalMessage;
        }
        public void AddAdditionalMessage(string additionalMessage)
        {
            this.additionalMessage = additionalMessage;
        }
    }
}
