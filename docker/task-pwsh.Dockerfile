# PowerShell task image for script runs (Part B, M5; SD-044). PowerShell 7.5
# and only Microsoft.Graph.Authentication + Microsoft.Graph.Users 2.41.2,
# pinned, with no package source left registered. It trusts this
# deployment's facade CA, which only the facade proxy's certificate chains to.
#
# Build with the CA's public directory as the named context `facade_ca`
# (written by `clw facade-ca-init`; it holds ca.crt alone, so no key reaches
# the Docker daemon):
#   docker build --build-context facade_ca=secrets/facade/public \
#       -f docker/task-pwsh.Dockerfile -t clw-task-pwsh:m5 .
FROM mcr.microsoft.com/powershell:7.5-ubuntu-24.04@sha256:042240d57ec9e47e511033b92625a8d95875ee5860af3015992c248b58a8be81
RUN pwsh -NoProfile -Command "Set-PSRepository PSGallery -InstallationPolicy Trusted; \
    Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.41.2 -Scope AllUsers -Force; \
    Install-Module Microsoft.Graph.Users -RequiredVersion 2.41.2 -Scope AllUsers -Force; \
    Unregister-PSRepository PSGallery" \
 && useradd --uid 10006 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin script
COPY --from=facade_ca ca.crt /usr/local/share/ca-certificates/clw-facade-ca.crt
RUN update-ca-certificates
COPY task_pwsh/bootstrap.ps1 /clw/bootstrap.ps1
USER 10006:10006
ENV HOME=/tmp
ENTRYPOINT ["pwsh", "-NoProfile", "-NonInteractive", "-File", "/clw/bootstrap.ps1"]
