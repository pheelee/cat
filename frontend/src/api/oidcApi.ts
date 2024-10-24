import { ErrorResponse, handleReponse } from "./api"

export type OIDCConfig = {
    metadata_url: string,
    public_client : boolean,
    pkce: boolean,
    response_type: ResponseType,
    client_id: string,
    secret: string,
    redirect_uri: string,
    scopes: string[],
    tokens: Tokens,
    error_response: ErrorResponse
}

export type Tokens = {
    access_token: string,
    id_token: string
}

export type ResponseType = {
    code: boolean,
    token: boolean,
    id_token: boolean
}

export default {
    get: () => fetch('/api/oidc').then(handleReponse) as Promise<OIDCConfig>,
    put: (data: OIDCConfig) => fetch('/api/oidc', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    }).then(handleReponse) as Promise<OIDCConfig>,
}
