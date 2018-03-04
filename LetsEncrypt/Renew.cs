namespace JayKayDesign.MailEnable.LetsEncrypt
{
    using NLog;
    using System;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    internal static class Renew
    {
        internal static void DoWork()
        {
            var logger = LogManager.GetCurrentClassLogger();

            try
            {
                MailEnable mailenable = new MailEnable();
                string[] certificateHosts = mailenable
                    .FindHostNames()
                    .Union(Properties.Settings.Default.AdditionalMailHosts.Split(',')).ToArray();

                if (certificateHosts.Length == 0)
                {
                    logger.Fatal("Mailenable has no postoffices or domains set up.");
                    return;
                }

                if (certificateHosts.Length > 100)
                {
                    logger.Fatal("LetsEncrypt does not allow more than 100 domain names in one certificate.");
                    return;
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


                if (!website.Create())
                {
                    logger.Fatal("Could not create website.");
                    return;
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

                if (!certificate.MakeCertificate())
                {
                    logger.Fatal("Could not generate certificate");
                    website.Remove();
                    return;
                }

                mailenable.StopServices();

                X509Certificate2 cert = certificate.InstallCertificate(certificate.PathToCertificate);
                if (cert == null)
                {
                    mailenable.StartServices();
                    return;
                }

                website.InstallCertificate(cert, Properties.Settings.Default.ExistingWebsiteTlsHost);
                mailenable.InstallCertificate(cert);

                website.Remove();
                mailenable.StartServices();

                logger.Info("Successfully renewed MailEnable certificate");

                Schedule.ScheduleTask(Properties.Settings.Default.ScheduledTaskName, Properties.Settings.Default.RefreshIntervalDays);

            }
            catch (Exception ex)
            {
                logger.Fatal(ex);
            }
        }

    }
}

