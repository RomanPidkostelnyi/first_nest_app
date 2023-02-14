import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { Prisma } from "@prisma/client";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) {    }

    async signup(dto: AuthDto) {
        const hash = await argon.hash(dto.password);

        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
                select: {
                    id: true,
                    email: true,
                    createdAt: true
                }
            })
    
            return user;
        } catch (error) {
            console.log({error})
            if(error instanceof  Prisma.PrismaClientKnownRequestError) {
                if(error.code === 'P2002') {
                    throw new ForbiddenException('Credentials taken');
                }
            }
        }
    }

    async signin(dto: AuthDto) {
        const user = await this.prisma.user.findFirst({
            where: {
                email: dto.email,
            },
        });

        if(!user) {
            throw new ForbiddenException('Credentials incorrect')
        }

        const pwMatches = await argon.verify(
          user.hash,
          dto.password  
        );

        if (!pwMatches) {
            throw new ForbiddenException('Credentials incorrect')
        } 

        return this.signToken(user.id, user.email);
    }

    signToken(userId: number, email: string): {
        access_token: Promise<string>;
    } {
        const payload = {
            sub: userId,
            email
        }

        const token = this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: this.config.get('JWT_SECRET')
        })

        return {
            access_token: token
        }
    }

}
