# Script analyser image (Part B, M4; SD-043). PowerShell 7.5 and only
# Microsoft.Graph.Authentication (for its offline cmdlet metadata), pinned.
# The runner starts it with no network, a read-only root, no credentials,
# and the script on stdin; analyse.ps1 parses it and never executes it.
FROM mcr.microsoft.com/powershell:7.5-ubuntu-24.04@sha256:042240d57ec9e47e511033b92625a8d95875ee5860af3015992c248b58a8be81
RUN pwsh -NoProfile -Command "Set-PSRepository PSGallery -InstallationPolicy Trusted; \
    Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.41.2 -Scope AllUsers -Force; \
    Unregister-PSRepository PSGallery" \
 && useradd --uid 10005 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin analyser
# The cmdlet-to-endpoint index, built once here rather than per analysis (SD-044).
COPY task_pwsh/build_command_index.ps1 /clw/build_command_index.ps1
RUN pwsh -NoProfile -NonInteractive -File /clw/build_command_index.ps1 /clw/graph-commands.json
COPY task_pwsh/analyse.ps1 /clw/analyse.ps1
USER 10005:10005
ENV HOME=/tmp
ENTRYPOINT ["pwsh", "-NoProfile", "-NonInteractive", "-File", "/clw/analyse.ps1"]
