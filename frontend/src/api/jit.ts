import { handleReponse } from "./api"

export type User = {
    id: string
    protocol: string
	display_name: string
	first_name: string
	last_name: string
	email: string
	roles: string[]
}

export type Config = {
    enabled: boolean
    update_on_login: boolean
    saml_mappings: claims
    oidc_mappings: claims
}

export type claims = {
    display_name: string
    first_name: string
    last_name: string
    email: string
    roles: string
}

export default {
    getUsers: () => fetch('/api/jit/users').then(handleReponse) as Promise<User[]>,
    getConfig: () => fetch('/api/jit').then(handleReponse) as Promise<Config>,
    postConfig: (data: Config) => fetch('/api/jit', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    }).then(handleReponse) as Promise<Config>
}
