import { ConflictException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { LoginDto, RegisterDto } from './dto';
import { UserService } from '@user/user.service';
import { Tokens } from './interfaces';
import { compareSync } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Token, User } from '@prisma/client';
import { PrismaService } from '@prisma/prisma.service';
import { v4 } from 'uuid';
import { add } from 'date-fns';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly prismaService: PrismaService
    ) { }

    async register(dto: RegisterDto) {
        const user = await this.userService.findOne(dto.email);

        if (user) {
            throw new ConflictException('Пользователь с таким email уже зарегистрирован');
        }

        return this.userService.save(dto).catch(err => {
            this.logger.error(err);
            return null;
        });
    }

    async login(dto: LoginDto, userAgent: string): Promise<Tokens> {
        const user = await this.userService.findOne(dto.email);

        if (!user || !compareSync(dto.password, user.password)) {
            throw new UnauthorizedException('Неверный логин или пароль');
        }

        return this.generateTokens(user, userAgent);
    }

    async refresh(token: string, userAgent: string): Promise<Tokens> {
        if (!token) {
            throw new UnauthorizedException();
        }

        const tokenData = await this.prismaService.token.delete({
            where: { token }
        });

        if (!tokenData) {
            throw new UnauthorizedException();
        }

        if (new Date(tokenData.exp) < new Date()) {
            throw new UnauthorizedException();
        }

        const user = await this.userService.findOne(tokenData.userId);

        return this.generateTokens(user, userAgent);
    }

    private async generateTokens(user: User, userAgent: string): Promise<Tokens> {
        const accessToken = 'Bearer ' + this.jwtService.sign({
            id: user.id,
            email: user.email,
            roles: user.roles
        });

        const refreshToken = await this.getRefreshToken(user.id, userAgent);

        return {
            accessToken,
            refreshToken
        };
    }

    private async getRefreshToken(userId: string, userAgent: string): Promise<Token> {
        const token = await this.prismaService.token.findFirst({
            where: {
                userId,
                userAgent
            }
        });

        // если нашелся токен, то обновляем у него token и exp
        // если нет, то создаем новый
        return this.prismaService.token.upsert({
            where: {
                token: token ? token.token : ''
            },
            update: {
                token: v4(),
                exp: add(new Date(), { months: 1 }),
            },
            create: {
                token: v4(),
                exp: add(new Date(), { months: 1 }),
                userId,
                userAgent
            }
        });
    }
}
