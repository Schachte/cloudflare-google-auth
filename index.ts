import { PEM_HEADER, PEM_FOOTER } from "./constants"

// GoogleOAuth encapsulates the logic required to retrieve an access token
// for the OAuth flow.
class GoogleOAuth {
    objectToBase64url = (object: object) =>
        this.arrayBufferToBase64Url(new TextEncoder().encode(JSON.stringify(object)))

    arrayBufferToBase64Url = (buffer: ArrayBuffer) =>
        btoa(String.fromCharCode(...new Uint8Array(buffer)))
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')

    str2ab = (str: string) => {
        const buf = new ArrayBuffer(str.length)
        const bufView = new Uint8Array(buf)
        for (let i = 0, strLen = str.length; i < strLen; i += 1) {
            bufView[i] = str.charCodeAt(i)
        }
        return buf
    }

    sign = async (content: string, signingKey: string) => {
        const buf = this.str2ab(content)
        const plainKey = signingKey
            .replace(PEM_HEADER, '')
            .replace(PEM_FOOTER, '')
            .replace(/(\r\n|\n|\r)/gm, '')
        const binaryKey = this.str2ab(atob(plainKey))
        const signer = await crypto.subtle.importKey(
            'pkcs8',
            binaryKey,
            {
                name: 'RSASSA-PKCS1-V1_5',
                hash: { name: 'SHA-256' },
            },
            false,
            ['sign'],
        )
        const binarySignature = await crypto.subtle.sign(
            { name: 'RSASSA-PKCS1-V1_5' },
            signer,
            buf,
        )
        return this.arrayBufferToBase64Url(binarySignature)
    }

    getGoogleAuthToken = async (
        user: string,
        key: string,
        scope: string,
    ): Promise<string | undefined> => {
        const jwtHeader = this.objectToBase64url({ alg: 'RS256', typ: 'JWT' })
        try {
            const assertiontime = Math.round(Date.now() / 1000)
            const expirytime = assertiontime + 3600
            const claimset = this.objectToBase64url({
                iss: user,
                scope,
                aud: 'https://oauth2.googleapis.com/token',
                exp: expirytime,
                iat: assertiontime,
            })

            const jwtUnsigned = `${jwtHeader}.${claimset}`
            const signedJwt = `${jwtUnsigned}.${this.sign(jwtUnsigned, key)}`
            const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${signedJwt}`
            const response = await fetch('https://oauth2.googleapis.com/token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Cache-Control': 'no-cache',
                    Host: 'oauth2.googleapis.com',
                },
                body,
            })
            const { access_token } = await response.json()
            return access_token
        } catch (err) {
            console.error(err)
            return undefined
        }
    }
}
