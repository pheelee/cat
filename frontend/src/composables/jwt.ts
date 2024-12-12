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

export const prettyToken = (token: any) => {
    return JSON.stringify(token, null, 3).replace(/^( *)("[\w]+": )?("[^"]*"|[\w.+-]*)?([,[{])?$/mg, function (match, pIndent, pKey, pVal, pEnd) {
        const key = '<span class=json-key>';
        const val = '<span class=json-value>';
        const str = '<span class=json-string>';
        let r = pIndent || '';
        if (pKey)
            r = r + key + pKey.replace(/[": ]/g, '') + '</span>: ';
        if (pVal)
            r = r + (pVal[0] == '"' ? str : val) + pVal + '</span>';
        return r + (pEnd || '');
    })
}
