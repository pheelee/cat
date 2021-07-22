module github.com/pheelee/Cat

go 1.16

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/crewjam/saml v0.4.5
	github.com/go-xmlfmt/xmlfmt v0.0.0-20191208150333-d5b6f63a941b
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	golang.org/x/oauth2 v0.0.0-20210628180205-a41e5a781914
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)

replace github.com/crewjam/saml v0.4.5 => github.com/pheelee/saml v0.4.6-0.20210722072116-da8ec38262f6
