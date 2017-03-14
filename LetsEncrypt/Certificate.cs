using ACMESharp;
using ACMESharp.ACME;
using ACMESharp.HTTP;
using ACMESharp.JOSE;
using ACMESharp.PKI;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace JayKayDesign.MailEnable.LetsEncrypt
{
    internal class Certificate
    {
        internal ILog Logger { get; set; }

        private static AcmeClient client;

        private string acmeUri;
        private string mainDomain;
        private string[] alternateNames;
        private string configurationPath;
        private string configPath;
        private string certificatePath;
        private string websitePath;
        private string contactEmail;
        private int keyLength;

        public string PathToCertificate { get; set; }

        internal Certificate(string acmeUri, string mainDomain, string[] alternateNames, string configurationPath, string contactEmail, int keyLength, string websitePath)
        {
            this.acmeUri = acmeUri;
            this.mainDomain = mainDomain;
            this.alternateNames = alternateNames.Where(a => a != mainDomain).ToArray();
            this.configurationPath = configurationPath;
            this.websitePath = websitePath;
            this.contactEmail = contactEmail;
            this.keyLength = keyLength;

            configPath = Path.Combine(configurationPath, "config");
            if (!Directory.Exists(configPath))
            {
                Directory.CreateDirectory(configPath);
            }

            certificatePath = Path.Combine(configurationPath, "certificate");
            if (!Directory.Exists(certificatePath))
            {
                Directory.CreateDirectory(certificatePath);
            }

        }

        internal bool MakeCertificate()
        {
            try
            {
                using (var signer = new RS256Signer())
                {
                    signer.Init();

                    var signerPath = Path.Combine(configPath, "Signer");
                    if (File.Exists(signerPath))
                    {
                        Logger.Log(LogLevel.Information, $"Loading Signer from {signerPath}");
                        using (var signerStream = File.OpenRead(signerPath))
                        {
                            signer.Load(signerStream);
                        }
                    }

                    using (client = new AcmeClient(new Uri(acmeUri), new AcmeServerDirectory(), signer))
                    {
                        client.Init();
                        client.GetDirectory(true);

                        var registrationPath = Path.Combine(configPath, "Registration");
                        if (File.Exists(registrationPath))
                        {
                            Logger.Log(LogLevel.Information, $"Loading Registration from {registrationPath}");
                            using (var registrationStream = File.OpenRead(registrationPath))
                            {
                                client.Registration = AcmeRegistration.Load(registrationStream);
                            }
                        }
                        else
                        {
                            var email = "mailto:" + contactEmail;
                            var registration = client.Register(new string[] { email });

                            client.UpdateRegistration(true, true);

                            using (var registrationStream = File.OpenWrite(registrationPath))
                            {
                                client.Registration.Save(registrationStream);
                            }

                            using (var signerStream = File.OpenWrite(signerPath))
                            {
                                signer.Save(signerStream);
                            }
                        }

                        List<AuthorizationState> authStatus = Authorize();

                        if(authStatus.Any(a=> a.Status == "invalid"))
                        {
                            return false;
                        }

                        PathToCertificate = RequestCertificate();
                    }
                }
            }
            catch (Exception e)
            {
                var acmeWebException = e as AcmeClient.AcmeWebException;
                if (acmeWebException != null)
                {
                    Logger.Log(LogLevel.Fatal, acmeWebException.Message);
                    Logger.Log(LogLevel.Fatal, "ACME Server Returned:");
                    Logger.Log(LogLevel.Fatal, acmeWebException.Response.ContentAsString);
                }
                else
                {
                    Logger.Log(LogLevel.Fatal, e);
                }

                return false;
            }

            return true;
        }

        internal X509Certificate2 InstallCertificate(string certFile)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            foreach (var c in store.Certificates)
            {
                if (c.GetNameInfo(X509NameType.DnsName, false) == Properties.Settings.Default.MainDomain)
                {
                    this.Logger.Log(LogLevel.Information, "Removing old certificate from store");
                    store.Certificates.Remove(c);
                }
            }

            X509Certificate2 cert = new X509Certificate2(certFile, "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
            cert.FriendlyName = mainDomain;
            store.Add(cert);
            store.Close();

            return cert;
        }

        private List<AuthorizationState> Authorize()
        {
            List<string> allDomains = new List<string>();
            allDomains.Add(this.mainDomain);
            allDomains.AddRange(this.alternateNames);

            List<AuthorizationState> authStatus = new List<AuthorizationState>();
            foreach (var domain in allDomains)
            {
                Logger.Log(LogLevel.Information, $"\nAuthorizing Identifier {domain} Using Challenge Type {AcmeProtocol.CHALLENGE_TYPE_HTTP}");
                var authState = client.AuthorizeIdentifier(domain);
                var challenge = client.DecodeChallenge(authState, AcmeProtocol.CHALLENGE_TYPE_HTTP);
                var httpChallenge = challenge.Challenge as HttpChallenge;

                // We need to strip off any leading '/' in the path
                var filePath = httpChallenge.FilePath;
                if (filePath.StartsWith("/", StringComparison.OrdinalIgnoreCase))
                {
                    filePath = filePath.Substring(1);
                }
                var answerPath = Path.Combine(this.websitePath, filePath);

                Logger.Log(LogLevel.Information, $" Writing challenge answer to {answerPath}");
                var directory = Path.GetDirectoryName(answerPath);
                Directory.CreateDirectory(directory);
                File.WriteAllText(answerPath, httpChallenge.FileContent);

                var answerUri = new Uri(httpChallenge.FileUrl);
                Logger.Log(LogLevel.Information, $"Answer should now be browsable at {answerUri}");

                Logger.Log(LogLevel.Information, "Submitting answer");
                authState.Challenges = new AuthorizeChallenge[] { challenge };
                client.SubmitChallengeAnswer(authState, AcmeProtocol.CHALLENGE_TYPE_HTTP, true);

                // have to loop to wait for server to stop being pending.
                // TODO: put timeout/retry limit in this loop
                int timeout = 10;
                while (authState.Status == "pending" && timeout > 0)
                {
                    Logger.Log(LogLevel.Information, "Refreshing authorization");
                    Thread.Sleep(2000);
                    var newAuthzState = client.RefreshIdentifierAuthorization(authState);

                    if (newAuthzState.Status != "pending")
                    {
                        authState = newAuthzState;
                    }

                    timeout--;
                }

                if (timeout == 0)
                {
                    Logger.Log(LogLevel.Error, string.Format("Timeout waiting for {0}", domain));
                    authStatus.Add(authState);

                    return authStatus;
                }

                Logger.Log(LogLevel.Information, $"Authorization Result: {authState.Status}");

                if (authState.Status == "invalid")
                {
                    Logger.Log(LogLevel.Error, string.Format("Authorization Failed {0}", authState.Status));
                    Logger.Log(LogLevel.Error, string.Format("Full Error Details {0}", authState));
                    Logger.Log(LogLevel.Error, $"The ACME server was probably unable to reach {answerUri}");
                }

                authStatus.Add(authState);
            }

            return authStatus;
        }

        private string RequestCertificate()
        {
            var cp = CertificateProvider.GetProvider();
            var rsaPkp = new RsaPrivateKeyParams();
            rsaPkp.NumBits = this.keyLength;
            var rsaKeys = cp.GeneratePrivateKey(rsaPkp);

            var csrDetails = new CsrDetails
            {
                CommonName = this.mainDomain,
                AlternativeNames = this.alternateNames.Except(new string[] { this.mainDomain})
            };
            var csrParams = new CsrParams
            {
                Details = csrDetails,
            };
            var csr = cp.GenerateCsr(csrParams, rsaKeys, Crt.MessageDigest.SHA256);

            byte[] derRaw;
            using (var bs = new MemoryStream())
            {
                cp.ExportCsr(csr, EncodingFormat.DER, bs);
                derRaw = bs.ToArray();
            }
            var derB64U = JwsHelper.Base64UrlEncode(derRaw);

            Logger.Log(LogLevel.Information, $"\nRequesting Certificate");
            var certRequ = client.RequestCertificate(derB64U);

            Logger.Log(LogLevel.Information, $" Request Status: {certRequ.StatusCode}");

            if (certRequ.StatusCode == System.Net.HttpStatusCode.Created)
            {
                var keyGenFile = Path.Combine(certificatePath, $"{this.mainDomain}-gen-key.json");
                var keyPemFile = Path.Combine(certificatePath, $"{this.mainDomain}-key.pem");
                var csrGenFile = Path.Combine(certificatePath, $"{this.mainDomain}-gen-csr.json");
                var csrPemFile = Path.Combine(certificatePath, $"{this.mainDomain}-csr.pem");
                var crtDerFile = Path.Combine(certificatePath, $"{this.mainDomain}-crt.der");
                var crtPemFile = Path.Combine(certificatePath, $"{this.mainDomain}-crt.pem");
                string crtPfxFile = Path.Combine(certificatePath, $"{this.mainDomain}-all.pfx");

                using (var fs = new FileStream(keyGenFile, FileMode.Create))
                {
                    cp.SavePrivateKey(rsaKeys, fs);
                }
                using (var fs = new FileStream(keyPemFile, FileMode.Create))
                {
                    cp.ExportPrivateKey(rsaKeys, EncodingFormat.PEM, fs);
                }
                using (var fs = new FileStream(csrGenFile, FileMode.Create))
                {
                    cp.SaveCsr(csr, fs);
                }
                using (var fs = new FileStream(csrPemFile, FileMode.Create))
                {
                    cp.ExportCsr(csr, EncodingFormat.PEM, fs);
                }

                Logger.Log(LogLevel.Information, $" Saving Certificate to {crtDerFile}");
                using (var file = File.Create(crtDerFile))
                {
                    certRequ.SaveCertificate(file);
                }

                Crt crt;
                using (FileStream source = new FileStream(crtDerFile, FileMode.Open),
                    target = new FileStream(crtPemFile, FileMode.Create))
                {
                    crt = cp.ImportCertificate(EncodingFormat.DER, source);
                    cp.ExportCertificate(crt, EncodingFormat.PEM, target);
                }

                // To generate a PKCS#12 (.PFX) file, we need the issuer's public certificate
                var isuPemFile = GetIssuerCertificate(certRequ, cp);

                Logger.Log(LogLevel.Information, $" Saving Certificate to {crtPfxFile}");
                using (FileStream source = new FileStream(isuPemFile, FileMode.Open),
                    target = new FileStream(crtPfxFile, FileMode.Create))
                {
                    try
                    {
                        var isuCrt = cp.ImportCertificate(EncodingFormat.PEM, source);
                        cp.ExportArchive(rsaKeys, new[] { crt, isuCrt }, ArchiveFormat.PKCS12, target);
                    }
                    catch (Exception ex)
                    {
                        Logger.Log(LogLevel.Error, $"Error exporting archive: {ex.Message.ToString()}");
                    }
                }

                cp.Dispose();

                return crtPfxFile;
            }

            throw new Exception($"Request status = {certRequ.StatusCode}");
        }

        private string GetIssuerCertificate(CertificateRequest certificate, CertificateProvider cp)
        {
            var linksEnum = certificate.Links;
            if (linksEnum != null)
            {
                var links = new LinkCollection(linksEnum);
                var upLink = links.GetFirstOrDefault("up");
                if (upLink != null)
                {
                    var tmp = Path.GetTempFileName();
                    try
                    {
                        using (var web = new WebClient())
                        {
                            var uri = new Uri(new Uri(acmeUri), upLink.Uri);
                            web.DownloadFile(uri, tmp);
                        }

                        var cacert = new X509Certificate2(tmp);
                        var sernum = cacert.GetSerialNumberString();

                        var cacertDerFile = Path.Combine(certificatePath, $"ca-{sernum}-crt.der");
                        var cacertPemFile = Path.Combine(certificatePath, $"ca-{sernum}-crt.pem");

                        if (!File.Exists(cacertDerFile))
                            File.Copy(tmp, cacertDerFile, true);

                        Logger.Log(LogLevel.Information, $" Saving Issuer Certificate to {cacertPemFile}");
                        if (!File.Exists(cacertPemFile))
                            using (FileStream source = new FileStream(cacertDerFile, FileMode.Open),
                                target = new FileStream(cacertPemFile, FileMode.Create))
                            {
                                var caCrt = cp.ImportCertificate(EncodingFormat.DER, source);
                                cp.ExportCertificate(caCrt, EncodingFormat.PEM, target);
                            }

                        return cacertPemFile;
                    }
                    finally
                    {
                        if (File.Exists(tmp))
                        {
                            File.Delete(tmp);
                        }
                    }
                }
            }

            return null;
        }

    }
}
