import cors from 'cors'
import express from 'express';
import querystring from 'query-string'
import cookieParser from 'cookie-parser'
import { config } from 'dotenv';
import { verify } from "jsonwebtoken";
import { addUser, createAccessToken, validCookies } from "./auth";
import { generateRandomString, stateKey, getSpotifyTokens } from "./spotify-tokens";
import bodyParser from 'body-parser'

(async () => {
    config()

    const app = express(); // create express app
    app.use(cookieParser()) // use cookie parser middleware
    app.use(bodyParser.json())
    app.use(cors({
        origin: "http://localhost:3000",
        credentials: true
    }))

    app.get("/", (_req, res) => { res.send("Hello world Spotify API w/ JWT") })

    // refresh token route
    app.post("/refresh_token", async (req, res) => {
        let payload: any = null
        const { token, valid } = validCookies(req.cookies) // get the refresh token stored in cookies named 'jid'

        // check if token has cookies
        if (!valid) return res.send({ message: "No token provided", ok: false, accessToken: '' })

        try { // verify the refresh token
            payload = verify(token, process.env.REFRESH_TOKEN_SECRET!)
        } catch (error) { // if the provided refresh token is invalid
            return res.send({ message: "Invalid token", ok: false, accessToken: '' })
        }
        // return a new access token if all validated
        return res.send({ message: "Successfully authenticated!", ok: true, accessToken: await createAccessToken(payload.userId, { req, res }) })
    })

    // redirected route to spotify login to get tokens
    app.get('/login', (req, res) => {
        // check for password in header
        // check if refresh token exists in cookies
        const { valid } = validCookies(req.cookies)
        if (valid) return res.json({ message: "Already authenticated" }) // return

        try {
            var state = generateRandomString(16);
            res.cookie(stateKey, state);

            // your application requests authorization
            var scope = 'user-read-private playlist-modify-public playlist-modify-private user-read-email';
            res.redirect('https://accounts.spotify.com/authorize?' +
                querystring.stringify({
                    response_type: 'code',
                    client_id: process.env.CLIENT_ID,
                    scope: scope,
                    redirect_uri: process.env.REDIRECT_URL,
                    state: state
                }));
        } catch (error) {
            console.log(`[ERROR] ${error.message}`);
            res.send(error.message)
        }
    })

    // redirect route from /login containing the response from spotify
    app.get('/callback', async (req, res) => {
        // your application requests refresh and access tokens
        // after checking the state parameter
        const code = req.query.code || null;
        const state = req.query.state || null;
        const storedState = req.cookies ? req.cookies[stateKey] : null;

        if (state === null || state !== storedState) res.json({ error: 'state_mismatch' })
        // if (state === null || state !== storedState) res.redirect('/auth?' + querystring.stringify({ error: 'state_mismatch' }))
        else {
            res.clearCookie(stateKey);
            const { access_token, refresh_token } = await getSpotifyTokens(code?.toString()!)
            addUser({ access_token, refresh_token }, { res, req })
        }
    });

    app.listen(8888, () => console.log("Started server in port 8888"))
})()