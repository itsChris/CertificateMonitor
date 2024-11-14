using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CertificateMonitor.Interfaces
{
    public interface ICertificateService
    {
        Task<X509Certificate2> GetCertificateAsync(string url);
    }
}
