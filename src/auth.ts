import { Response, Request } from 'express'
import { sign, verify } from "jsonwebtoken";
import { MiddlewareFn } from "type-graphql"
import { getAuthUser, refreshSpotifyToken } from "./spotify-tokens";

export interface MyContext {
    res: Response
    req: Request
    payload?: { userId: string, spotifyAccessToken: string }
}

export interface AuthObj {
    refresh_token: string
    access_token: string
}

// Authorization: Bearer <token>
export const isAuthenticated: MiddlewareFn<MyContext> = ({ context }, next) => {
    const authorization = context.req.headers['authorization']

    if (!authorization) throw new Error("Not authenticated!")

    try {
        const token = authorization.split(" ")[1]
        const payload = verify(token, process.env.ACCESS_TOKEN_SECRET!)
        context.payload = payload as any

    } catch (error) {
        if (error.name === "TokenExpiredError") throw new Error("Token Expired!")
        if (error.name === "JsonWebTokenError") throw new Error("Token Invalid!")
        throw new Error(error.name)
    }
    return next()
}

// check the token cookies are valid
export const validCookies = (cookies: any): { valid: boolean, token: string } => {
    const tokens = [cookies['a1_h'], cookies['a1_b'], cookies['a1_p']]
    if (tokens.includes(undefined)) return { valid: false, token: "" }
    return { valid: true, token: tokens.join(".") }
}

// create a new access token with jwt
export const createAccessToken = async (userId: string, { req }: MyContext) => {
    // get the refersh token from the cookies and use it to refresh the spotify token
    let payload: any;
    const { token: refresh_token, valid } = validCookies(req.cookies)
    if (!valid) throw new Error("Unable to get refresh token!")

    try { // verify the refresh token
        payload = verify(refresh_token, process.env.REFRESH_TOKEN_SECRET!)
    } catch (error) { // if the provided refresh token is invalid
        throw new Error("Invalid refresh token")
    }

    const token = await refreshSpotifyToken({ client_id: process.env.CLIENT_ID!, client_secret: process.env.CLIENT_SECRET! }, payload.refreshToken) as any
    return sign(
        { userId, spotifyAccessToken: token.access_token },
        process.env.ACCESS_TOKEN_SECRET!,
        { expiresIn: '1m' })
}

// create a refresh token with jwt
export const createRefreshToken = (userId: string, token: string) => {
    return sign(
        {
            userId,
            refreshToken: token
        },
        process.env.REFRESH_TOKEN_SECRET!, { expiresIn: '7d' })
}

// set the refresh token to cookies
export const setRefreshToken = (token: string, res: Response) => {
    const [a1_h, a1_b, a1_p] = token.split(".") // break the code

    res.cookie(
        'a1_h', a1_h,
        { httpOnly: true, path: "/refresh_token" }
    )

    res.cookie(
        'a1_b', a1_b,
        { httpOnly: true, path: "/refresh_token" }
    )

    res.cookie(
        'a1_p', a1_p,
        { httpOnly: true, path: "/refresh_token" }
    )
}

// add authenticated user to db
export const addUser = async ({ access_token, refresh_token }: AuthObj, { res, req }: MyContext) => {
    try {
        const { id, email } = await getAuthUser(access_token) as any
        if (!id || !email) res.send("Error getting user")
        const jwt_enc_refresh_token = createRefreshToken(id, refresh_token) // get refresh token
        setRefreshToken(jwt_enc_refresh_token, res) // set cookie
        res.redirect(req.headers.referer || "/")
    } catch (error) {
        console.log(error.name, error.message);
        res.redirect(req.headers.referer || "/")
    }
}
