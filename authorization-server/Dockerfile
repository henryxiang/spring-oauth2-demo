# Build stage
FROM maven:3.9.4-eclipse-temurin-17 AS build

WORKDIR /app

# IMPORTANT: If you build with docker-compose and the build context is the module folder,
# you cannot access the parent pom.xml. Prefer setting the build context to the project root
# and point to this Dockerfile via dockerfile: authorization-server/Dockerfile.
# Assuming build context is project root:
COPY pom.xml ./pom.xml
COPY authorization-server/pom.xml authorization-server/pom.xml
COPY authorization-server/src authorization-server/src

RUN mvn -f authorization-server/pom.xml clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:17-jre-jammy

# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app
COPY --from=build /app/authorization-server/target/*.jar app.jar
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:9000/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
