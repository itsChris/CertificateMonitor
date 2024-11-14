using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CertificateMonitor.Interfaces;
using Microsoft.Extensions.Logging;

namespace CertificateMonitor.Services
{
    public class CertificateChecker
    {
        private readonly ILogger<CertificateChecker> _logger;
        private readonly ICertificateService _certificateService;

        public CertificateChecker(ILogger<CertificateChecker> logger, ICertificateService certificateService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _certificateService = certificateService ?? throw new ArgumentNullException(nameof(certificateService));
        }

        public async Task CheckCertificatesAsync(IEnumerable<string> urls)
        {
            if (urls == null)
            {
                _logger.LogError("No URLs provided to check.");
                return;
            }

            foreach (var url in urls)
            {
                try
                {
                    _logger.LogInformation("Checking certificate for: {Url}", url);
                    var certificate = await _certificateService.GetCertificateAsync(url);

                    if (certificate != null)
                    {
                        LogCertificateDetails(certificate);
                    }
                    else
                    {
                        _logger.LogWarning("No certificate retrieved for {Url}.", url);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "An error occurred while checking the certificate for {Url}.", url);
                }
            }
        }

        private void LogCertificateDetails(X509Certificate2 certificate)
        {
            try
            {
                // Basic certificate information
                _logger.LogInformation("Issuer: {Issuer}", certificate.Issuer);
                _logger.LogInformation("Subject: {Subject}", certificate.Subject);
                _logger.LogInformation("Valid from: {NotBefore}", certificate.NotBefore);
                _logger.LogInformation("Valid until: {NotAfter}", certificate.NotAfter);
                _logger.LogInformation("Serial Number: {SerialNumber}", certificate.SerialNumber);
                _logger.LogInformation("Thumbprint: {Thumbprint}", certificate.Thumbprint);
                _logger.LogInformation("Signature Algorithm: {SignatureAlgorithm}", certificate.SignatureAlgorithm.FriendlyName);
                _logger.LogInformation("Public Key Algorithm: {PublicKeyAlgorithm}", certificate.PublicKey.Oid.FriendlyName);
                _logger.LogInformation("Public Key: {PublicKey}", BitConverter.ToString(certificate.PublicKey.EncodedKeyValue.RawData));
                _logger.LogInformation("Friendly Name: {FriendlyName}", certificate.FriendlyName);

                var daysRemaining = (certificate.NotAfter - DateTime.UtcNow).Days;
                _logger.LogInformation("Days until expiration: {DaysRemaining}", daysRemaining);

                // Subject Alternative Names (SANs)
                try
                {
                    var sanExtension = certificate.Extensions["2.5.29.17"];
                    if (sanExtension != null)
                    {
                        _logger.LogInformation("Subject Alternative Names (SANs): {SANs}", sanExtension.Format(true));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse Subject Alternative Names (SANs).");
                }

                // Enhanced Key Usages (EKUs)
                try
                {
                    var ekuCollection = certificate.Extensions["2.5.29.37"] as X509EnhancedKeyUsageExtension;
                    if (ekuCollection != null)
                    {
                        foreach (var oid in ekuCollection.EnhancedKeyUsages)
                        {
                            _logger.LogInformation("Enhanced Key Usage: {Usage}", oid.FriendlyName);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse Enhanced Key Usages.");
                }

                // Key Usage
                try
                {
                    var keyUsageExtension = certificate.Extensions["2.5.29.15"] as X509KeyUsageExtension;
                    if (keyUsageExtension != null)
                    {
                        _logger.LogInformation("Key Usage: {KeyUsages}", keyUsageExtension.KeyUsages);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse Key Usage.");
                }

                // Certificate Policies
                try
                {
                    var policyExtension = certificate.Extensions["2.5.29.32"];
                    if (policyExtension != null)
                    {
                        _logger.LogInformation("Certificate Policies: {Policies}", policyExtension.Format(true));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse Certificate Policies.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while logging certificate details.");
            }
        }

    }
}
