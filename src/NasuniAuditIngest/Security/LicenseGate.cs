using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace NasuniAuditIngest.Security;

/// <summary>Local-only guard. This is NOT a production license verifier.</summary>
public sealed class LicenseGate(IConfiguration configuration, IHostEnvironment environment)
{
    public void EnsureCollectionAllowed()
    {
        var mode = configuration["License:Mode"] ?? "development";

        if (mode.Equals("development", StringComparison.OrdinalIgnoreCase))
        {
            if (!environment.IsDevelopment())
                throw new InvalidOperationException(
                    "Development license mode is permitted only when DOTNET_ENVIRONMENT=Development.");

            Console.Error.WriteLine(
                "WARNING: development license mode enabled; do not use for production.");
            return;
        }

        throw new InvalidOperationException(
            $"License mode '{mode}' has no provider implemented. Collection is blocked.");
    }
}
