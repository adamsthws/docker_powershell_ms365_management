FROM mcr.microsoft.com/dotnet/sdk:9.0

# Fake xdg-open: prints the auth URL instead of trying to launch a browser (none exists in-container)
RUN printf '#!/bin/sh\n{ echo ""; echo ">>> Open this URL in your browser: $1"; echo ""; } > /dev/tty 2>&1 || true\necho "$1" > /tmp/auth_url.txt\n' > /usr/local/bin/xdg-open \
    && chmod +x /usr/local/bin/xdg-open

# Azure CLI (standalone binary, not a PowerShell module)
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Install MS365 modules
RUN pwsh -NoLogo -NonInteractive -Command " \
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Install-Module Microsoft.Graph -Scope AllUsers -Force; \
    Install-Module Microsoft.Graph.Beta -Scope AllUsers -Force; \
    Install-Module ExchangeOnlineManagement -Scope AllUsers -Force; \
    Install-Module PnP.PowerShell -Scope AllUsers -Force; \
    Install-Module MicrosoftTeams -Scope AllUsers -Force; \
    Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope AllUsers -Force; \
    Install-Module Microsoft.PowerApps.PowerShell -Scope AllUsers -AllowClobber -Force; \
    Install-Module Az -Scope AllUsers -Force; \
    Install-Module Microsoft365DSC -Scope AllUsers -Force; \
    Install-Module Pester -MinimumVersion 5.5.0 -Scope AllUsers -Force -SkipPublisherCheck; \
    Install-Module PSScriptAnalyzer -Scope AllUsers -Force \
    "

WORKDIR /root
ENTRYPOINT ["pwsh"]
