using ME = MailEnable.Administration;

namespace JayKayDesign.MailEnable.LetsEncrypt
{
    using Microsoft.Win32;
    using NLog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using System.ServiceProcess;

    internal class MailEnable
    {
        private List<string> stoppedServices;

        private static Logger logger = LogManager.GetLogger("MailEnable");

        public MailEnable()
        {
        }

        internal string[] GetPostofficeDomainsNames()
        {
            var postoffice = new ME.Postoffice();
            var domain = new ME.Domain();

            List<string> postofficeNames = new List<string>();
            List<string> domainNames = new List<string>();

            if (postoffice.FindFirstPostoffice() == 1)
            {
                do
                {
                    postofficeNames.Add(postoffice.Name);
                    postoffice.Name = string.Empty;
                    postoffice.Status = -1;

                } while (postoffice.FindNextPostoffice() == 1);
            }

            foreach (string postofficeName in postofficeNames)
            {
                domain.AccountName = postoffice.Name;
                domain.DomainName = string.Empty;
                domain.Status = -1;
                domain.DomainRedirectionHosts = string.Empty;
                domain.DomainRedirectionStatus = -1;

                if (domain.FindFirstDomain() == 1)
                {
                    do
                    {
                        domainNames.Add(domain.DomainName);

                        domain.AccountName = postoffice.Name;
                        domain.DomainName = string.Empty;
                        domain.Status = -1;
                        domain.DomainRedirectionHosts = string.Empty;
                        domain.DomainRedirectionStatus = -1;
                    } while (domain.FindNextDomain() == 1);
                }
            }

            logger.Debug("Found {0} domains. {1}", domainNames.Count, string.Join(", ", domainNames));

            return domainNames.ToArray();
        }

        internal string[] FindHostNames()
        {
            IPAddress serverIp = Properties.Settings.Default.ServerIP == "*" 
                ? IPAddress.Any 
                : new IPAddress(Properties.Settings.Default.ServerIP.Split('.').Select(i => byte.Parse(i)).ToArray());

            List<string> certificateHosts = new List<string>();

            foreach (string postofficeDomain in GetPostofficeDomainsNames())
            {
                foreach (string hostName in Properties.Settings.Default.ValidMailHosts.Split(','))
                {
                    IPHostEntry dnsInfo;
                    string mailHost = hostName + "." + postofficeDomain;
                    try
                    {
                        dnsInfo = Dns.GetHostEntry(mailHost);
                    }
                    catch (Exception ex)
                    {
                        logger.Warn("Host {0}: {1}", mailHost, ex.Message);
                        continue;
                    }

                    if (dnsInfo.AddressList.Length == 0)
                    {
                        logger.Warn("Could not resolve host: {0}",mailHost);
                    }
                    else if (!dnsInfo.AddressList.Any(a => a.Equals(serverIp)))
                    {
                        logger.Warn("Host {0} is not served by {1}", mailHost,serverIp);
                        certificateHosts.Add(mailHost);
                    }
                    else
                    {
                        logger.Debug("Found valid host: {0}", mailHost);
                        certificateHosts.Add(mailHost);
                    }
                }
            }

            return certificateHosts.ToArray();
        }

        internal void InstallCertificate(X509Certificate2 cert)
        {
            string certName = cert.SubjectName.Name;

            string registryKey = @"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Mail Enable\Mail Enable\Security";
            string registryValue = "Default SSL Certificate";

            string value = (string)Registry.GetValue(registryKey, registryValue, null);
            if (value == null)
            {
                Registry.SetValue(registryKey, registryValue, certName);
                logger.Info("Added SSL binding for Mailenable.");
            }
            else if (value != certName)
            {
                Registry.SetValue(registryKey, registryValue, certName);
                logger.Info("Changed SSL binding for Mailenable from {0} to {1}.", value, certName);
            }
            else
            {
                logger.Debug("SSL binding for Mailenable already set.");
            }
        }

        internal void StopServices()
        {
            stoppedServices = new List<string>();

            foreach (string serviceName in new string[] { "MEIMAPS", "MEPOPS", "MESMTPCS", "MEPOPCS" })
            {
                using (var s = ME.Service.GetServiceControllerIfExists(serviceName))
                {
                    if (s != null && s.Status == ServiceControllerStatus.Running)
                    {
                        s.Stop();
                        stoppedServices.Add(serviceName);
                        logger.Info("Stopping {0}", s.DisplayName);
                    }
                }
            }
        }

        internal void StartServices()
        {
            foreach (string serviceName in stoppedServices)
            {
                using (var s = ME.Service.GetServiceControllerIfExists(serviceName))
                {
                    if (s.Status != ServiceControllerStatus.Running && s.Status != ServiceControllerStatus.StartPending)
                    {
                        s.Start();
                        logger.Info("Starting {0}", s.DisplayName);
                    }
                }
            }
        }
    }
}
