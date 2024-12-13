import { handleReponse } from "./api"

export type User = {
	id: string
	display_name: string
	first_name: string
	last_name: string
	email: string
	roles: string[]
}

export type Config = {
    enabled: boolean
}

export const mockUsers = [
    {
        id: '1',
        display_name: 'John Doe',
        first_name: 'John',
        last_name: 'Doe',
        email: 'X2lYy@example.com',
        roles: ['admin']
    },
    {
        id: '2',
        display_name: 'Jane Doe',
        first_name: 'Jane',
        last_name: 'Doe',
        email: 'X2lYy@example.com',
        roles: ['admin', 'editor']
    },
    {
        id: '3',
        display_name: 'John Doe',
        first_name: 'John',
        last_name: 'Doe',
        email: 'X2lYy@example.com',
        roles: ['viewer']
    },
]

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