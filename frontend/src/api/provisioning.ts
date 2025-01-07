import { handleReponse } from "./api"

export enum Strategy {
    JIT = 0,
    SCIM = 1
}

export type SCIMLog = {
    timestamp: string
    method: string
    url: string
    status_code: number
    headers: string[]
    request: string
    response: string
}

export type Provisioning = {
    // list of users that were provisioned
    users: Map<string, User>
    // map of group names with a list of users that belong to the group
    groups: Map<string, User[]>
    // config contains the configuration for JIT and SCIM
    config: Config
}

export type Config = {
    // enable provisioning
    enabled: boolean
    // Provisioning strategy, 0 means JIT and 1 means SCIM
    strategy: Strategy
    // jit contains the configuration for JIT
    jit: JIT
    // scim contains the configuration for SCIM
    scim: SCIM
}

export type User = {
    id: string
    protocol: string
	display_name: string
	first_name: string
	last_name: string
	email: string
	roles: string[]
}

export type JIT = {
    update_on_login: boolean
    saml_mappings: claims
    oidc_mappings: claims
}

export type SCIM = {
    url: string
    token: string
}

export type claims = {
    display_name: string
    first_name: string
    last_name: string
    email: string
    roles: string
}

export default {
    getUsers: () => fetch('/api/provisioning/users').then(handleReponse) as Promise<Map<string,User>>,
    getGroups: () => fetch('/api/provisioning/groups').then(handleReponse) as Promise<Map<string, User[]>>,
    getConfig: () => fetch('/api/provisioning').then(handleReponse) as Promise<Config>,
    postConfig: (data: Config) => fetch('/api/provisioning', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    }).then(handleReponse) as Promise<Config>,
    getSCIMLog: () => fetch('/api/provisioning/scim/log').then(handleReponse) as Promise<SCIMLog[]>
}
