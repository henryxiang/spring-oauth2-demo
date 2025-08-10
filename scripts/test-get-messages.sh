#!/usr/bin/env bash

ACCESS_TOKEN=$(curl -u resource-server-client:resource-secret \
  -d "grant_type=client_credentials&scope=message.read message.write" \
  http://localhost:9000/oauth2/token | awk -F '"' '{print $4}')
MESSAGE=$(date)

curl -v -X GET \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/api/messages
