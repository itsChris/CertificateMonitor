using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using CertificateMonitor.Interfaces;
using CertificateMonitor.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;

namespace CertificateMonitor
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // Configure Serilog for structured logging
            Log.Logger = new LoggerConfiguration()
                .WriteTo.Console()
                .WriteTo.File("logs/certificateMonitor.log", rollingInterval: RollingInterval.Day)
                .CreateLogger();

            try
            {
                var serviceCollection = new ServiceCollection();
                ConfigureServices(serviceCollection);

                using var serviceProvider = serviceCollection.BuildServiceProvider();
                var certificateChecker = serviceProvider.GetRequiredService<CertificateChecker>();

                var configuration = serviceProvider.GetRequiredService<IConfiguration>();
                var urlsToCheck = configuration.GetSection("UrlsToCheck").Get<List<string>>();

                if (urlsToCheck == null || urlsToCheck.Count == 0)
                {
                    Log.Error("No URLs found in configuration to check.");
                    return;
                }

                await certificateChecker.CheckCertificatesAsync(urlsToCheck);
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "An unhandled exception occurred in the application.");
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        private static void ConfigureServices(IServiceCollection services)
        {
            // Dependency injection and configuration setup
            services.AddSingleton<ICertificateService, CertificateService>();
            services.AddSingleton<CertificateChecker>();
            services.AddHttpClient();
            services.AddLogging(loggingBuilder =>
            {
                loggingBuilder.ClearProviders();
                loggingBuilder.AddSerilog();
            });

            services.AddSingleton<IConfiguration>(new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build());
        }
    }
}
