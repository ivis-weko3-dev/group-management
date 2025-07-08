#!/bin/bash
docker compose down
docker compose -f docker-compose-sentinel.yml up -d --build

docker compose exec nginx pip3 install -e /group-management/module/group-management
docker compose exec nginx supervisorctl restart all
