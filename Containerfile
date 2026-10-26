# Build once, promote the same image. Base images are pinned by digest (refresh with Dependabot/Renovate or by hand).
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:0eeb52c76e35a5431ca707ad2bc75e38006a05393045d8532ae44c15d9474523 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props nuget.config Gatekeeper.slnx ./
COPY src/ src/
# global.json is not copied: the SDK image is pinned by digest (10.0.4xx), the repo pin is the local/CI 10.0.1xx band.
# Locked-mode restore: fails if a packages.lock.json no longer matches the project.
RUN dotnet restore src/Gatekeeper.Api/Gatekeeper.Api.csproj --locked-mode
RUN dotnet publish src/Gatekeeper.Api/Gatekeeper.Api.csproj -c Release --no-restore -o /out --no-self-contained

# Chiseled runtime: no shell, no package manager, non-root user.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled@sha256:8c20ba8cb64c498f2fb98f2aed374b7f144aa5b603270989e7c141545a04d380
WORKDIR /app
# Links the GHCR package to this repository (the workflow token can then pull it).
LABEL org.opencontainers.image.source=https://github.com/sookmoo/gatekeeper
COPY --from=build /out .
USER $APP_UID
# The container must bind a non-loopback address. The API speaks plain HTTP and refuses that unless explicitly
# allowed; set Gatekeeper__AllowNonLoopback=true at deploy time and publish the port on 127.0.0.1 or behind TLS.
# "Urls" (app configuration) must be used: it overrides appsettings.json, ASPNETCORE_URLS does not.
ENV Urls=http://+:8080 \
    DOTNET_EnableDiagnostics=0
EXPOSE 8080
# No HEALTHCHECK here (OCI images ignore it); the Quadlet unit sets HealthCmd with the "healthcheck" command.
ENTRYPOINT ["dotnet", "Gatekeeper.Api.dll"]
