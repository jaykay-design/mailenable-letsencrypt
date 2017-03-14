namespace JayKayDesign.MailEnable.LetsEncrypt
{
    internal interface ILog
    {
        void Log(LogLevel level, object message);
    }

    internal enum LogLevel
    {
        None,
        Information,
        Error,
        Fatal
    }

}
