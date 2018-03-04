namespace JayKayDesign.MailEnable.LetsEncrypt
{
    using Microsoft.Web.Administration;
    using NLog;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    internal class Website
    {
        private string existingWebsiteName;
        private string[] hostNames;
        private IEnumerable<Binding> existingBindings;
        private string serverIp;
        private string newWebsitePath;
        private string mainDomain;

        private bool createNewWebsite;
        private long currentWebsiteId;

        private readonly string webConfig = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<configuration>
  <system.webServer>
    <staticContent>
      <mimeMap fileExtension=""."" mimeType=""text/json"" />
    </staticContent>
  </system.webServer>
  <system.web>
    <authorization>
      <allow users = ""*""/>
    </authorization>
  </system.web>
<system.webServer>
    <rewrite>
        <rules>
            <remove name=""ForceHTTPS"" />
        </rules>
    </rewrite>
</system.webServer>

</configuration>";

        private static Logger logger = LogManager.GetLogger("Website");

        internal string WebsiteRoot { get; private set; }

        internal Website(string[] hostNames, string serverIp, string mainDomain, string existingWebsiteName = null, string newWebsitePath = null)
        {
            this.hostNames = hostNames;
            this.serverIp = serverIp;
            this.mainDomain = mainDomain;
            this.existingWebsiteName = existingWebsiteName;
            this.newWebsitePath = newWebsitePath;

            this.createNewWebsite = !string.IsNullOrEmpty(newWebsitePath);

            this.existingBindings = null;
        }

        internal bool Create()
        {
            Remove();

            using (ServerManager iisManager = new ServerManager())
            {
                Site site;
                if (this.createNewWebsite)
                {
                    site = iisManager.Sites.Add(
                        "MailEnableLetsEncrypt",
                        "http",
                         serverIp + ":80:" + this.mainDomain,
                        this.newWebsitePath);

                    existingBindings = new List<Binding>();
                    site.ServerAutoStart = true;
                    WebsiteRoot = this.newWebsitePath;
                }
                else
                {
                    site = iisManager.Sites.FirstOrDefault(s => s.Name == this.existingWebsiteName);
                    if (site == null)
                    {
                        logger.Fatal("Could not find website with name {0}.", existingWebsiteName);
                        return false;
                    }

                    existingBindings = site.Bindings.ToList();
                    WebsiteRoot = site.Applications["/"].VirtualDirectories["/"].PhysicalPath;
                }

                foreach (string host in hostNames.Union(new string[] { mainDomain }).Except(existingBindings.Select(b => b.Host)))
                {
                    site.Bindings.Add(this.serverIp + ":80:" + host, "http");
                    logger.Debug("Adding host {0} to website {1}", host, site.Name);
                }

                iisManager.CommitChanges();

                currentWebsiteId = site.Id;
            }

            string acmePath = Path.Combine(WebsiteRoot, ".well-known");
            if (!Directory.Exists(acmePath))
            {
                Directory.CreateDirectory(acmePath);
            }

            using (var file = File.CreateText(Path.Combine(acmePath, "web.config")))
            {
                file.Write(this.webConfig);
            }

            return true;
        }

        internal void Remove()
        {
            if (existingBindings == null)
            {
                return;
            }

            using (ServerManager iisManager = new ServerManager())
            {
                string pathToDelete;
                if (this.createNewWebsite)
                {
                    Site existingWebsite = iisManager.Sites.FirstOrDefault(s => s.Name == "MailEnableLetsEncrypt");
                    if (existingWebsite != null)
                    {
                        iisManager.Sites.Remove(existingWebsite);
                    }

                    pathToDelete = this.WebsiteRoot;
                }
                else
                {

                    Site existingWebsite = iisManager.Sites.FirstOrDefault(s => s.Name == this.existingWebsiteName);

                    if (existingWebsite != null)
                    {
                        foreach (Binding binding in existingWebsite.Bindings.Where(b => !existingBindings.Any(eb => eb.Host == b.Host)).ToList())
                        {
                            existingWebsite.Bindings.Remove(binding);
                            logger.Debug("Removing host {0} from website {1}", binding.Host, existingWebsite.Name);
                        }
                    }

                    pathToDelete = Path.Combine(WebsiteRoot, ".well-known");
                }

                iisManager.CommitChanges();

                if (Directory.Exists(pathToDelete))
                {
                    try
                    {
                        Directory.Delete(pathToDelete, true);
                    }
                    catch { }
                }
            }

            currentWebsiteId = 0;
        }

        internal void InstallCertificate(X509Certificate2 cert, string httpsHostName)
        {
            using (ServerManager iisManager = new ServerManager())
            {
                Site currentWebsite = iisManager.Sites.First(s => s.Id == currentWebsiteId);

                Binding httpsBinding = currentWebsite.Bindings.FirstOrDefault(b => b.Protocol == "https" && b.Host == httpsHostName);
                if (httpsBinding != null)
                {
                    logger.Info("Removing old SSL binding from MailEnable website");
                    currentWebsite.Bindings.Remove(httpsBinding);
                }

                logger.Info("Adding new SSL binding to MailEnable website");

                currentWebsite.Bindings.Add($"{serverIp}:443:{httpsHostName}", cert.GetCertHash(), "My");

                iisManager.CommitChanges();
            }
        }
    }
}