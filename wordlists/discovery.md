# Content Discovery Wordlist

Paths, files, and endpoints for content discovery and forced browsing against
web apps and APIs. Group by category so you can run a focused list instead of a
single giant one.

Usage:

```bash
# fuzz a single category (copy a block into cat.txt first)
ffuf -w cat.txt -u https://target/FUZZ -mc 200,204,301,302,401,403

# or feed the whole list
ffuf -w discovery.txt -u https://target/FUZZ -ac
```

## Table of contents

1. [Admin and Debug Panels](#admin-and-debug-panels)
2. [API Endpoints](#api-endpoints)
3. [WordPress Endpoints](#wordpress-endpoints)
4. [Authentication and OAuth Endpoints](#authentication-and-oauth-endpoints)
5. [Backup and Exposed Files](#backup-and-exposed-files)
6. [Cloud Resources and Storage](#cloud-resources-and-storage)
7. [Configuration Files](#configuration-files)
8. [Service Worker and JavaScript Files](#service-worker-and-javascript-files)
9. [Common Extensions for Sensitive Files](#common-extensions-for-sensitive-files)
10. [Miscellaneous Sensitive Endpoints](#miscellaneous-sensitive-endpoints)
11. [Redirect and Notification Endpoints](#redirect-and-notification-endpoints)
12. [Case-Sensitive Variations](#case-sensitive-variations)

## Admin and Debug Panels

```text
admin
admin.php
admin.html
admin/
dashboard
dashboard.php
controlpanel
cpanel
admin-panel
admin/login
admin/auth
debug
debug.php
debug/
metrics
METRICS
actuator
actuator/health
actuator/env
admin/config
admin/settings
dashboard/admin
debug/info
trace
TRACE
```

## API Endpoints

```text
api
api/v1
api/v2
api/v3
rest
rest/v1
graphql
api/config
api/settings
api/users
api/admin
api/auth
api/keys
api/token
api/v1/config
api/v1/users
api/v1/admin
rest/admin
rest/config
graphql/admin
api/debug
api/status
api/health
```

## WordPress Endpoints

```text
/wp-config.php-backup
/wp-config.php.orig
/wp-config.php.swp
/wp-config-sample.php
/wp-config.inc
/wp-config.old
/wp-config.txt
/wp-config.php.txt
/wp-config.php.bak
/wp-config.php.old
/wp-config.php.dist
/wp-config.php.inc
/wp-config.php.swp
/wp-config.php.html
/wp-config-backup.txt
/wp-config.php.save
/wp-config.php~
/wp-config.php.original
/_wpeprivate/config.json
```

## Authentication and OAuth Endpoints

```text
oauth
oauth/authorize
auth
login
signup
register
password
reset
forgot-password
auth/token
oauth/callback
auth/login
auth/register
auth/reset
oauth/v1
oauth2
oauth2/authorize
```

## Backup and Exposed Files

```text
backup
backup.zip
backup.tar.gz
backup.sql
db.sql
database.sql
site.bak
backup.bak
data.zip
archive.tar
backup.gz
site.sql
db.bak
backup/
backups/
data/
archive/
```

## Cloud Resources and Storage

```text
storage
files
s3
bucket
storage/
files/
s3.amazonaws.com
s3/
storage/files
uploads
uploads/
public/
assets/
```

## Configuration Files

```text
config
config.json
settings
settings.json
.env
.env.local
.env.dev
.env.prod
config.xml
settings.xml
web.config
app.config
config.ini
wp-config.php
configuration
configuration.json
config.yaml
config.yml
.env.bak
.env.example
```

## Service Worker and JavaScript Files

```text
service-worker.js
sw.js
worker.js
manifest.json
app.js
main.js
bundle.js
scripts.js
config.js
init.js
serviceworker.js
```

## Common Extensions for Sensitive Files

```text
.bak
.zip
.tar.gz
.sql
.config
.ini
.yml
.yaml
.json
.xml
.php
.js
.txt
.log
.gz
.tar
.conf
.bkp
.save
~1
~2
```

## Miscellaneous Sensitive Endpoints

```text
phpinfo.php
info.php
test
test.php
dev
dev/
staging
staging/
internal
internal/
private
private/
.git
.git/config
.htaccess
robots.txt
sitemap.xml
crossdomain.xml
clientaccesspolicy.xml
server-status
status
health
env
version
changelog
readme
README
README.md
changelog.txt
swagger
swagger.json
swagger.yaml
openapi.json
openapi.yaml
logs
log
access.log
error.log
logs/
```

## Redirect and Notification Endpoints

```text
redirect
redirect/
callback
webhook
webhooks
webhook/
notify
notification
push
redirect.php
callback/
webhooks/
```

## Case-Sensitive Variations

```text
ADMIN
CONFIG
DEBUG
METRICS
STATUS
HEALTH
API
REST
GRAPHQL
BACKUP
STORAGE
FILES
```
