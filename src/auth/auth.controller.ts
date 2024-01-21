import { BadRequestException, Body, Controller, Get, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';
import { Tokens } from './interfaces';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { Cookie, UserAgent } from '@common/decorators';

const REFRESH_TOKEN = 'refresh-token';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly configService: ConfigService
    ) { }

    @Post('register')
    async register(@Body() dto: RegisterDto) {
        const user = await this.authService.register(dto);

        if (!user) {
            throw new BadRequestException(`Не получается зарегистрировать пользователя с данными ${JSON.stringify(dto)}`);
        }
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
}
