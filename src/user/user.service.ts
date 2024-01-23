import { JwtPayload } from '@auth/interfaces';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { Role, User } from '@prisma/client';
import { PrismaService } from '@prisma/prisma.service';
import { genSaltSync, hashSync } from 'bcrypt';

@Injectable()
export class UserService {
    constructor(private readonly prismaService: PrismaService) { }

    save(user: Partial<User>) {
        return this.prismaService.user.create({
            data: {
                email: user.email,
                password: user.password ? hashSync(user.password, genSaltSync(10)) : null,
                provider: user.provider,
                roles: ['USER'],
            },
        });
    }

    findOne(idOrEmail: string) {
        return this.prismaService.user.findFirst({
            where: {
                OR: [
                    { id: idOrEmail },
                    { email: idOrEmail }
                ],
            },
        });
    }

    delete(id: string, user: JwtPayload) {
        console.log(id, user.id, user.roles);
        if (user.id == id || !user.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException();
        }

        return this.prismaService.user.delete({
            where: { id },
            select: { id: true }
        });
    }
}
