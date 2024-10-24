import { ErrorResponse } from "./api"

export type SAMLConfig = {
    idp_url: string
    idp_metadata: string
    sp_entity_id: string
    sp_metadata_url: string
    request_signing: boolean
    request_signing_algo: string
    add_encryption_cert: boolean
    allow_idp_initiated: boolean
    name_id_format: string
    certificates: {
        primary: certificate
        secondary: certificate
    }
    saml_assertion: SAMLAssertion
    error_response: ErrorResponse
}

export type SAMLAssertion = {
    sub: string
    iss: string
    aud: string
    iat: number
    nbf: number
    exp: number
    attr: {
        [key: string]: string[]
    }
}

type certificate = {
    name: string
    certificate: string
}

export default {
    get: () => fetch('/api/saml').then(res => res.json() as Promise<SAMLConfig>),
    put: (data: SAMLConfig) => fetch('/api/saml', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    }).then(res => res.json() as Promise<SAMLConfig>),

}
