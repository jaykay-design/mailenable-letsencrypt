using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using ME = MailEnable.Administration;

namespace JayKayDesign.MailEnable.LetsEncrypt
{
    internal class MailEnable
    {
        public ILog Logger { get; set; }

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

            Logger.Log(LogLevel.Information, string.Format("Found {0} domains. {1}", domainNames.Count, string.Join(", ", domainNames)));

            return domainNames.ToArray();
        }

        internal string[] FindHostNames()
        {
            IPAddress serverIp = new IPAddress(Properties.Settings.Default.ServerIP.Split('.').Select(i => byte.Parse(i)).ToArray());
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
                    catch (SocketException ex)
                    {
                        Logger.Log(LogLevel.Information, "Host " + mailHost + " " + ex.Message);
                        continue;
                    }
                    catch (Exception ex)
                    {
                        Logger.Log(LogLevel.Error, "Host " + mailHost + " " + ex);
                        continue;
                    }

                    if (dnsInfo.AddressList.Length == 0)
                    {
                        Logger.Log(LogLevel.Information, "Could not resolve host:" + mailHost);
                    }
                    else if (!dnsInfo.AddressList.Any(a => a.Equals(serverIp)))
                    {
                        Logger.Log(LogLevel.Information, "Host " + mailHost + " is not served by " + serverIp.ToString());
                    }
                    else
                    {
                        Logger.Log(LogLevel.Information, "Found valid host:" + mailHost);
                        certificateHosts.Add(mailHost);
                    }
                }
            }

            return certificateHosts.ToArray();
        }

        internal bool InstallCertificate(X509Certificate2 cert)
        {
            string certName = cert.GetNameInfo(X509NameType.DnsName, false);

            string registryKey = @"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Mail Enable\Mail Enable\Security";
            string registryValue = "Default SSL Certificate";

            string value = (string)Registry.GetValue(registryKey, registryValue, null);
            if (value == null)
            {
                Logger.Log(LogLevel.Error, "No security section found in Mailenable's registry");
                return true;
            }
            else if ((string)Registry.GetValue(registryKey, "Default SSL Certificate", string.Empty) != certName)
            {
                Registry.SetValue(registryKey, "Default SSL Certificate", certName);
                Logger.Log(LogLevel.Information, "Added SSL binding for Mailenable.");
            }
            else {
                Logger.Log(LogLevel.Information, "SSL binding for Mailenable aready set.");
            }

            return true;
        }

        internal void StopServices()
        {
            foreach (string serviceName in new string[] { "MEIMAPS", "MEPOPS", "MESMTPCS", "MEPOPCS" })
            {
                using (var s = ME.Service.GetServiceControllerIfExists(serviceName))
                {
                    s.Stop();
                    Logger.Log(LogLevel.Information, "Stopping " + s.DisplayName);
                }
            }
        }
        internal void StartServices()
        {
            foreach (string serviceName in new string[] { "MEIMAPS", "MEPOPS", "MESMTPCS", "MEPOPCS" })
            {
                using (var s = ME.Service.GetServiceControllerIfExists(serviceName))
                {
                    s.Start();
                    Logger.Log(LogLevel.Information, "Starting " + s.DisplayName);
                }
            }
        }
    }
}
