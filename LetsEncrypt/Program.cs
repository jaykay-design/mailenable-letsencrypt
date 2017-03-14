using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace JayKayDesign.MailEnable.LetsEncrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            bool logToConsole = args.Contains("-logtoconsole");

            ILog logger = new Logger(logToConsole);

            do
            {
                try
                {
                    MailEnable mailenable = new MailEnable() { Logger = logger };
                    string[] certificateHosts = mailenable
                        .FindHostNames()
                        .Union(Properties.Settings.Default.AdditionalMailHosts.Split(',')).ToArray();

                    if (certificateHosts.Length == 0)
                    {
                        logger.Log(LogLevel.Information, "Mailenable has no postoffices or domains set up.");
                        break;
                    }

                    if (certificateHosts.Length > 100)
                    {
                        logger.Log(LogLevel.Fatal, "LetsEncrypt does not allow more than 100 domain names in one certificate.");
                        break;
                    }

                    Website website;
                    if (Properties.Settings.Default.CreateNewWebsite)
                    {
                        website = new Website(
                            certificateHosts,
                            Properties.Settings.Default.ServerIP,
                            Properties.Settings.Default.MainDomain,
                            null,
                            Properties.Settings.Default.WebsitePath);
                    }
                    else
                    {
                        website = new Website(
                            certificateHosts,
                            Properties.Settings.Default.ServerIP,
                            Properties.Settings.Default.MainDomain,
                            Properties.Settings.Default.ExistingWebsiteName);
                    }

                    website.Logger = logger;

                    if (!website.Create())
                    {
                        logger.Log(LogLevel.Fatal, "Could not create website.");
                        break;
                    }

                    string acmeUri = Properties.Settings.Default.Debug ? "https://acme-staging.api.letsencrypt.org/" : "https://acme-v01.api.letsencrypt.org/";

                    Certificate certificate = new Certificate(
                        acmeUri,
                        Properties.Settings.Default.MainDomain,
                        certificateHosts,
                        Properties.Settings.Default.StoragePath,
                        Properties.Settings.Default.Email,
                        Properties.Settings.Default.RSAKeyBits,
                        website.WebsiteRoot);

                    certificate.Logger = logger;

                    if (!certificate.MakeCertificate())
                    {
                        logger.Log(LogLevel.Fatal, "Could not generate certificate");
                        website.Remove();
                        break;
                    }

                    website.Remove();

                    mailenable.StopServices();

                    X509Certificate2 cert = certificate.InstallCertificate(certificate.PathToCertificate);
                    website.InstallCertificate(cert, Properties.Settings.Default.ExistingWebsiteTlsHost);
                    mailenable.InstallCertificate(cert);

                    mailenable.StartServices();

                    Schedule.ScheduleTask(Properties.Settings.Default.ScheduledTaskName, Properties.Settings.Default.RefreshIntervalDays);
                }
                catch (Exception ex)
                {
                    logger.Log(LogLevel.Fatal, ex);
                }

            } while (false);

            if (logToConsole)
            {
                Console.ReadKey();
            }
        }
    }
}
