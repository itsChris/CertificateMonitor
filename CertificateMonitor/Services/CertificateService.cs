using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CertificateMonitor.Interfaces;
using Microsoft.Extensions.Logging;

namespace CertificateMonitor.Services
{
    public class CertificateService : ICertificateService, IDisposable
    {
        private readonly ILogger<CertificateService> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private bool _disposed;

        public CertificateService(ILogger<CertificateService> logger, IHttpClientFactory httpClientFactory)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        }

        public async Task<X509Certificate2> GetCertificateAsync(string url)
        {
            try
            {
                X509Certificate2 certificate = null;

                // Create the custom HttpClientHandler for certificate handling
                using var httpClientHandler = new HttpClientHandler();
                httpClientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                {
                    if (cert != null)
                    {
                        certificate = new X509Certificate2(cert);
                    }
                    return true; // Allow the request to proceed.
                };

                // Use the handler directly with HttpClient, bypassing IHttpClientFactory
                using var httpClient = new HttpClient(httpClientHandler);
                _logger.LogDebug("Sending request to {Url}", url);
                httpClient.DefaultRequestHeaders.Add("User-Agent", "CertificateMonitor");

                // Send the request to retrieve the certificate
                await httpClient.GetAsync(url);

                if (certificate == null)
                {
                    throw new InvalidOperationException("Failed to retrieve a valid certificate.");
                }

                return certificate;
            }
            catch (HttpRequestException httpEx)
            {
                _logger.LogError(httpEx, "HTTP request error while retrieving certificate for {Url}", url);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error while retrieving certificate for {Url}", url);
                return null;
            }
        }


        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
        }
    }
}
