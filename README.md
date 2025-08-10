# Spring OAuth2 Demo

A multi-module Maven project demonstrating OAuth2 Authorization Server and Resource Server using Spring Boot 3.x and Spring Security 6.x.

## Project Structure

```
oauth2-microservices/
├── pom.xml                           # Parent POM
├── docker-compose.yml                # Docker Compose configuration
├── .dockerignore                     # Docker ignore file
├── README.md                         # This file
├── authorization-server/             # OAuth2 Authorization Server
│   ├── pom.xml
│   ├── Dockerfile
│   └── src/main/
│       ├── java/com/example/authserver/
│       │   └── AuthorizationServerApplication.java
│       └── resources/
│           └── application.yml
└── resource-server/                  # OAuth2 Resource Server
    ├── pom.xml
    ├── Dockerfile
    └── src/main/
        ├── java/com/example/resourceserver/
        │   ├── ResourceServerApplication.java
        │   ├── SecurityConfig.java
        │   └── MessageController.java
        └── resources/
            └── application.yml
```

## Services

### Authorization Server (Port 9000)
- OAuth2 Authorization Server with JWT tokens
- OpenID Connect support
- In-memory user store (user/password, admin/admin)
- Registered clients for resource server access

### Resource Server (Port 8080)
- Protected REST API with JWT validation
- Message CRUD operations
- Scope-based authorization (message.read, message.write)

## Running Locally

### Prerequisites
- Java 17+
- Maven 3.6+

### Build and Run
```bash
# Build all modules
mvn clean install

# Run Authorization Server (Terminal 1)
cd authorization-server
mvn spring-boot:run

# Run Resource Server (Terminal 2)
cd resource-server
mvn spring-boot:run
```

## Running with Docker

### Build and Run with Docker Compose
```bash
# Build and start all services
docker-compose up --build

# Run in background
docker-compose up -d --build

# Stop services
docker-compose down

# View logs
docker-compose logs -f authorization-server
docker-compose logs -f resource-server
```

### Build Individual Docker Images
```bash
# Build Authorization Server
docker build -t oauth2-auth-server -f authorization-server/Dockerfile .

# Build Resource Server
docker build -t oauth2-resource-server -f resource-server/Dockerfile .
```

## Testing the OAuth2 Flow

### 1. Get Access Token (Client Credentials)
```bash
curl -u resource-server-client:resource-secret \
  -d "grant_type=client_credentials&scope=message.read message.write" \
  http://localhost:9000/oauth2/token
```

### 2. Use Access Token to Call Protected API
```bash
# Get messages (requires message.read scope)
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8080/api/messages

# Add message (requires message.write scope)
curl -X POST \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '"Hello OAuth2!"' \
  http://localhost:8080/api/messages
```

### 3. Authorization Code Flow (Browser)
1. Navigate to: `http://localhost:9000/oauth2/authorize?response_type=code&client_id=resource-server-client&scope=message.read&redirect_uri=http://localhost:8080/authorized`
2. Login with user/password or admin/admin
3. Grant consent
4. Exchange authorization code for access token

## API Endpoints

### Authorization Server (http://localhost:9000)
- `GET /oauth2/authorize` - Authorization endpoint
- `POST /oauth2/token` - Token endpoint
- `GET /oauth2/jwks` - JSON Web Key Set
- `GET /.well-known/openid-configuration` - OpenID Connect Discovery

### Resource Server (http://localhost:8080)
- `GET /api/messages` - Get all messages (requires message.read)
- `POST /api/messages` - Add message (requires message.write)
- `GET /public/health` - Public health check

## Configuration

### Users
- user/password - Regular user with USER role
- admin/admin - Admin user with ADMIN and USER roles

### OAuth2 Clients
- resource-server-client - For resource server communication
  - Client ID: `resource-server-client`
  - Client Secret: `resource-secret`
  - Scopes: `message.read`, `message.write`, `user.read`, `openid`

### Scopes
- `message.read` - Read messages
- `message.write` - Create/update messages
- `user.read` - Read user information
- `openid` - OpenID Connect

## Docker Configuration

The Docker setup includes:
- Multi-stage builds for optimized image sizes
- Non-root user for security
- Health checks for service monitoring
- Proper networking between services
- Environment-specific configuration

## Security Features

- JWT tokens with RSA signing
- Scope-based authorization
- PKCE support for public clients
- OpenID Connect compliance
- Secure defaults and best practices

## Development Notes

- Authorization Server runs on port 9000
- Resource Server runs on port 8080
- JWT tokens are signed with dynamically generated RSA keys
- In-memory storage for simplicity (use databases in production)
- Debug logging enabled for OAuth2 flows

## Production Considerations

- Use external databases for user and client storage
- Implement proper key management (not in-memory)
- Add rate limiting and monitoring
- Use HTTPS in production
- Implement proper logging and auditing
- Consider using Redis for token storage
- Add comprehensive error handling

