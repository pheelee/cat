## v0.7.4 (2025-11-21)

### Fix

- **deps**: update all non-major dependencies (#118)

## v0.7.3 (2025-11-08)

### Fix

- **deps**: update module golang.org/x/oauth2 to v0.33.0 (#107)

## v0.7.2 (2025-11-05)

### Fix

- **deps**: update module github.com/minio/minio-go/v7 to v7.0.97 (#103)

## v0.7.1 (2025-10-28)

### Fix

- weird frontend build error in the vue-router
- **backend**: send default claims mapping for jit
- **frontend**: don't load data and logs if scim is not enabled

## v0.7.0 (2025-09-30)

### Feat

- add scim browser for user and groups

## v0.6.5 (2025-09-02)

### Fix

- **scim**: use uuid to avoid resource collision between users and groups
- check wether filtervalidator is not nil to avoid panic

## v0.6.4 (2025-08-19)

### Fix

- oidc redirect uri get overwritten by incorrect step assignment to stepper

## v0.6.3 (2025-06-12)

### Fix

- remove authorization header from output
- prevent deadlock situation when creating resources

## v0.6.2 (2025-03-04)

### Fix

- print version on startup

## v0.6.1 (2025-02-28)

### Fix

- **scim**: use mutex for memory resource handler to avoid collision when dealing with large data sets

## v0.6.0 (2025-02-07)

### Feat

- add s3 as storage backend

### Fix

- add saml acs error handling with feedback to the user

## v0.5.0 (2025-01-07)

### Feat

- add scim testing capability 😎

### Fix

- resource handler code taken from wrong example
- user must manually re-enable provisioning upon strategy change to pick up new settings
- persist session if SCIM was configured
- check SCIM setup upon sending logs

## v0.4.0 (2024-12-13)

### Feat

- enable customization of claims mapping for just in time provisioning
- make JIT feature opt-in
- initial commit for just in time provisioning feature

### Fix

- add white-space control to tokens
- return jit config after update
- separate roles by newline for saml assertion visualization
- update saml metadata when url changes
- don't persist saml idp metadata to reduce persistence space usage
- cleanup sessions that were unused or expired before persisting them

## v0.3.0 (2024-12-12)

### Feat

- add shared session mode for better persistence and collaboration with others

### Fix

- add feature branches to develop actions
- add github link to footer
- oidc callback for oauth2 has no id_token

## v0.2.5 (2024-11-05)

### Fix

- read issuer from metadata instead of string replacing the url

## v0.2.4 (2024-10-24)

### Refactor

- switch to vuetify frontend

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
