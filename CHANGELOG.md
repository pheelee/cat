## v0.2.3 (2024-09-23)

### Fix

- switch to session based certificate
- create a session based certificate to enable IdP certificate testing
- decouple session management and add persistence
- move session lifetime to command line params and default to 30 days

## v0.2.2 (2024-09-20)

### Fix

- properly shutdown session cleanup

## v0.2.1 (2024-09-17)

### Fix

- properly shutdown webserver on signals
- make lint and gosec happy
