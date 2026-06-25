# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy solution and project files
COPY ["SecureGate.sln", "."]
COPY ["src/SecureGate.API/SecureGate.API.csproj", "src/SecureGate.API/"]
COPY ["src/SecureGate.Core/SecureGate.Core.csproj", "src/SecureGate.Core/"]
COPY ["src/SecureGate.Infrastructure/SecureGate.Infrastructure.csproj", "src/SecureGate.Infrastructure/"]

# Restore dependencies
RUN dotnet restore "src/SecureGate.API/SecureGate.API.csproj"

# Copy source code
COPY . .

# Build and publish
WORKDIR "/src/src/SecureGate.API"
RUN dotnet build "SecureGate.API.csproj" -c Release -o /app/build
RUN dotnet publish "SecureGate.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# Create non-root user for security
RUN adduser --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

COPY --from=build /app/publish .

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
	CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080
EXPOSE 8081

ENTRYPOINT ["dotnet", "SecureGate.API.dll"]
