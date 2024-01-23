import { BadRequestException, Body, ClassSerializerInterceptor, Controller, Get, HttpStatus, Post, Query, Req, Res, UnauthorizedException, UseGuards, UseInterceptors } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';
import { Tokens } from './interfaces';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { Cookie, Public, UserAgent } from '@common/decorators';
import { UserResponse } from '@user/responses';
import { GoogleGuard } from './guards/google.guard';
import { HttpService } from '@nestjs/axios';
import { map, mergeMap, tap } from 'rxjs';
import { handleTimeoutAndErrors } from '@common/helpers';

const REFRESH_TOKEN = 'refresh-token';

@Public()
@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly configService: ConfigService,
        private readonly httpService: HttpService
    ) { }

    @UseInterceptors(ClassSerializerInterceptor)
    @Post('register')
    async register(@Body() dto: RegisterDto) {
        const user = await this.authService.register(dto);

        if (!user) {
            throw new BadRequestException(`Не получается зарегистрировать пользователя с данными ${JSON.stringify(dto)}`);
        }

        return new UserResponse(user);
    }

    @Post('login')
    async login(@Body() dto: LoginDto, @UserAgent() agent: string, @Res() res: Response) {
        const tokens = await this.authService.login(dto, agent);

        if (!tokens) {
            throw new BadRequestException(`Не получается авторизоваться пользователя с данными ${JSON.stringify(dto)}`);
        }

        this.setRefreshTokenToCookie(tokens, res);
    }

    @Get('refresh')
    async refresh(@Cookie(REFRESH_TOKEN) refreshToken: string, @UserAgent() agent: string, @Res() res: Response) {
        const tokens = await this.authService.refresh(refreshToken, agent);

        this.setRefreshTokenToCookie(tokens, res);
    }

    @Get('logout')
    async logout(@Cookie(REFRESH_TOKEN) refreshToken: string, @Res() res: Response) {
        await this.authService.deleteRefreshToken(refreshToken);

        res.clearCookie(REFRESH_TOKEN);

        res.sendStatus(HttpStatus.OK);
    }

    private setRefreshTokenToCookie(tokens: Tokens, res: Response) {
        if (!tokens) {
            throw new UnauthorizedException();
        }

        res.cookie(REFRESH_TOKEN, tokens.refreshToken.token, {
            httpOnly: true,
            sameSite: 'lax',
            expires: new Date(tokens.refreshToken.exp),
            secure: this.configService.get('NODE_ENV', 'development') === 'production',
            path: '/'
        });

        res.status(201).json({ accessToken: tokens.accessToken })
    }

    @UseGuards(GoogleGuard)
    @Get('google')
    googleAuth() { }

    @UseGuards(GoogleGuard)
    @Get('google/callback')
    googleAuthCallback(@Req() req: Request, @Res() res: Response) {
        // редирект на фронт
        const token = req.user['accessToken'];
        return res.redirect(`http://localhost:8080/api/auth/success?token=${token}`);
    }


    // данный запрос должен обрабатываться на фронте
    @Get('success')
    success(@Query('token') token: string, @UserAgent() agent: string, @Res() res: Response) {
        return this.httpService
            .get(`https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${token}`)
            .pipe(
                mergeMap(({ data: { email } }) => this.authService.googleAuth(email, agent)),
                map(data => this.setRefreshTokenToCookie(data, res)),
                handleTimeoutAndErrors()
            );
    }
}
