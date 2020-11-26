import request from 'request';

interface ClientKeys {
    client_id: string
    client_secret: string
}

interface SpotifyTokens {
    access_token: string
    refresh_token: string
}


// https://developer.spotify.com/documentation/web-api/

// NOTE: If Web API returns status code 429, it means that you have sent too many requests.When this happens, 
// check the Retry - After header, where you will see a number displayed.
// This is the number of seconds that you need to wait, before you try your request again.


export const stateKey = 'spotify_auth_state';
export const generateRandomString = (length: number) => {
    let text = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (var i = 0; i < length; i++) { text += possible.charAt(Math.floor(Math.random() * possible.length)); }
    return text;
};


export const refreshSpotifyToken = async ({ client_id, client_secret }: ClientKeys, refresh_token: string) => {
    const options = {
        url: "https://accounts.spotify.com/api/token",
        headers: { "Authorization": `Basic ${(Buffer.from(client_id + ':' + client_secret).toString('base64'))}` },
        form: {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        },
        json: true
    }

    return new Promise((resolve, reject) => {
        request.post(options, (err, res) => {
            if (res.statusCode === 200) {
                resolve(res.body)
            }
            reject(res.body)
        })
    })
}

export const getAuthUser = (token: string) => {
    const options = {
        url: "https://api.spotify.com/v1/me",
        headers: {
            "Authorization": `Bearer ${token}`,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
    }

    return new Promise((resolve, reject) => {
        request.get(options, (err, res) => {
            if (res.statusCode === 200) {
                resolve(JSON.parse(res.body))
            }
            reject(res.body)
        })
    })
}

export const getSpotifyTokens = (code: string) => {
    const authOptions = {
        url: 'https://accounts.spotify.com/api/token',
        form: {
            code: code,
            redirect_uri: process.env.REDIRECT_URL,
            grant_type: 'authorization_code'
        },
        headers: {
            'Authorization': 'Basic ' + (Buffer.from(process.env.CLIENT_ID + ':' + process.env.CLIENT_SECRET).toString('base64'))
        },
        json: true
    };

    return new Promise<SpotifyTokens>((resolve, reject) => {
        request.post(authOptions, (_error, response, body) => {
            if (response.statusCode === 200) resolve({ access_token: body.access_token, refresh_token: body.refresh_token })
            reject(response.body.error_description)
        })
    })
}