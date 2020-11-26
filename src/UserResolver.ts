import { Arg, Ctx, Field, Mutation, ObjectType, Query, Resolver, UseMiddleware } from "type-graphql";
import { User } from "./entity/User";
import { createAccessToken, isAuthenticated, MyContext } from "./auth";

@ObjectType()
class LoginResponse {
    @Field()
    accessToken: string
}


@Resolver()
export class UserResolver {
    // hello world
    @Query(() => String)
    test() { return 'Hi I am connected!' }

    // test function to check the middleware and protected routes
    @Query(() => String)
    @UseMiddleware(isAuthenticated)
    get_token(@Ctx() { payload }: MyContext) { return `Your access token is ${payload?.spotifyAccessToken}` }


    @Query(() => String)
    @UseMiddleware(isAuthenticated)
    async get_code(@Ctx() { payload }: MyContext) {
        const user = await User.findOne({ where: { user_id: payload?.userId } })
        return `Your spotify code is ${user?.spotify_code}`
    }

    // gets all users (SELECT)
    @Query(() => [User])
    users() { return User.find() }

    // handle login, send access and refresh tokens (VALIDATE)
    @Mutation(() => LoginResponse)
    async login(
        @Arg('email') email: string,
        // @Arg('password') password: string,
        @Ctx() { res, req }: MyContext
    ): Promise<LoginResponse> {
        const user = await User.findOne({ where: { email } })
        if (user === undefined) throw new Error("Not a valid user!")
        // if (user.password !== password) throw new Error("Incorrect password")

        // login successful
        // const { refresh_token } = await getSpotifyTokens(user.spotify_code)
        // console.log(refresh_token);
        // const jwt_enc_refresh_token = createRefreshToken(user!, refresh_token)
        // sendRefreshToken(jwt_enc_refresh_token, res)

        return {
            accessToken: await createAccessToken(user, { res, req }),
        }
    }
}