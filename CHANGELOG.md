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
