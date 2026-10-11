# Build once, promote the same image. Base images are pinned by digest (refresh with Dependabot/Renovate or by hand).
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:0eeb52c76e35a5431ca707ad2bc75e38006a05393045d8532ae44c15d9474523 AS build
WORKDIR /src
COPY Directory.Build.props Gatekeeper.slnx ./
COPY src/ src/
RUN dotnet publish src/Gatekeeper.Api/Gatekeeper.Api.csproj -c Release -o /out --no-self-contained

# Chiseled runtime: no shell, no package manager, non-root user.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled@sha256:8c20ba8cb64c498f2fb98f2aed374b7f144aa5b603270989e7c141545a04d380
WORKDIR /app
COPY --from=build /out .
USER $APP_UID
# The container must bind a non-loopback address. The API refuses that without authentication unless explicitly
# allowed; set Gatekeeper__AllowNonLoopback=true at deploy time and publish the port on 127.0.0.1 only.
# "Urls" (app configuration) must be used: it overrides appsettings.json, ASPNETCORE_URLS does not.
ENV Urls=http://+:8080 \
    DOTNET_EnableDiagnostics=0
EXPOSE 8080
# No HEALTHCHECK here (OCI images ignore it); the Quadlet unit sets HealthCmd with the "healthcheck" command.
ENTRYPOINT ["dotnet", "Gatekeeper.Api.dll"]
