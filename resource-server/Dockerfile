# Build stage
FROM maven:3.9.4-eclipse-temurin-17 AS build

WORKDIR /app

# Assuming build context is project root:
COPY pom.xml ./pom.xml
COPY resource-server/pom.xml resource-server/pom.xml
COPY resource-server/src resource-server/src

RUN mvn -f resource-server/pom.xml clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:17-jre-jammy

# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app
COPY --from=build /app/resource-server/target/*.jar app.jar
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8080/public/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
