namespace JayKayDesign.MailEnable.LetsEncrypt
{
    using System;

    class Program
    {
        static void Main(string[] args)
        {

            Renew.DoWork();

#if DEBUG
            Console.ReadKey();
#endif
        }
    }
}
