import { Response, Request } from 'express'
import { sign, verify } from "jsonwebtoken";
import { User } from "./entity/User";
import { MiddlewareFn } from "type-graphql"
import { getAuthUser, refreshSpotifyToken } from "./spotify-tokens";
import querystring from 'query-string'

export interface MyContext {
    res: Response
    req: Request
    payload?: { userId: string, spotifyAccessToken: string }
}

export interface AuthObj {
    refresh_token: string
    access_token: string
    code: string
}

// helper function to print the graphql db errors
const log_error_db = (err: any) => {
    console.log("---------------------------");
    console.error(`[DATABASE ERROR]\n\n[NAME] : ${err.name}\n[MESSAGE] : ${err.message}\n[ERR CODE] : ${err.code}\n[DETAIL] : ${err.detail}\n`);
    console.log("---------------------------");
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
export const createAccessToken = async (user: User, { req }: MyContext) => {
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
        { userId: user?.user_id, spotifyAccessToken: token.access_token },
        process.env.ACCESS_TOKEN_SECRET!,
        { expiresIn: '1m' })
}

// create a refresh token with jwt
export const createRefreshToken = (user: User, token: string) => {
    return sign(
        {
            userId: user?.user_id,
            tokenVersion: user.tokenVersion,
            refreshToken: token
        },
        process.env.REFRESH_TOKEN_SECRET!)
}

// set the refresh token to cookies
export const sendRefreshToken = (token: string, res: Response) => {
    const [a1_h, a1_b, a1_p] = token.split(".") // break the code

    res.cookie(
        'a1_h', a1_h,
        { httpOnly: true }
    )

    res.cookie(
        'a1_b', a1_b,
        { httpOnly: true }
    )

    res.cookie(
        'a1_p', a1_p,
        { httpOnly: true }
    )
}

// add authenticated user to db
export const addUser = async ({ access_token, refresh_token, code }: AuthObj, { res, req }: MyContext) => {
    const { id, email } = await getAuthUser(access_token) as any
    const random_password = Math.random().toString(36).slice(-8);

    try {
        await User.insert({
            user_id: id,
            email,
            spotify_code: code,
            password: random_password
        })


    } catch (err) {
        log_error_db(err)
        // primary key error
        if (err.code === "23505") User.update({ user_id: id }, { spotify_code: code })
        else {
            res.redirect("/auth?" + querystring.stringify({
                error: { [err.name]: err.message } as any
            }))
        }
    }


    const user = await User.findOne({ where: { user_id: id } }) // get inserted user 

    if (user) {
        const jwt_enc_refresh_token = createRefreshToken(user, refresh_token) // get refresh token
        sendRefreshToken(jwt_enc_refresh_token, res) // set cookie
        // res.redirect("/auth?" + querystring.stringify({
        //     password: random_password,
        //     data: "Success"
        // }))

        res.send("Ok")
    }
}