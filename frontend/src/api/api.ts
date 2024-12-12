import { SAMLAssertion } from "./samlApi"

export type ErrorResponse = {
    error: string
    error_description: string
}

export type Tokens = {
    access_token: string,
    id_token: string,
    saml_assertion: SAMLAssertion
}


export const handleReponse = async (response: Response) => {
    if (!response.ok) {
        return response.json()
            .catch(() => {
                throw new Error("Server responded with status code " + response.status)
            })
            .then(({ error }) => {
                throw new Error(error || response.status)
            })
    }
    return response.json()
}

export default {
    getTokens: () => fetch('/api/tokens').then(handleReponse) as Promise<Tokens>,
}
