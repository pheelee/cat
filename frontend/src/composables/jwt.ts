export type JWT = {
    header: {
        alg: string
        typ: string
    }
    payload: {
        iss: string
        sub: string
        aud: string
        exp: number
        iat: number
        nbf: number
        jti: string
        username: string
        [key: string]: any
    }
    signature: string
}


export const parseJwt = (token: string): JWT => {
    const header = JSON.parse(atob(token.split('.')[0]));
    const payload = JSON.parse(atob(token.split('.')[1]));
    const signature = token.split('.')[2];
    return { header, payload, signature };
}
