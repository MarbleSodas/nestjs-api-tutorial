import { ForbiddenException, Injectable } from "@nestjs/common";
import { User, Bookmark, Prisma } from '@prisma/client';
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto/auth.dto";
import * as argon from 'argon2';

@Injectable()

export class AuthService {

    constructor(private prisma: PrismaService) {}

    async signup(dto : AuthDto) {
        //generate password hash
        const hash = await argon.hash(dto.password);
        //save new user in db
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
            });
            //remove password hash from user object
            delete user.hash;
            //return saved user
            return user;

        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Email already exists');
                }
            }
            throw error;
        }
    }

    async signin(dto : AuthDto) {
        //find the user in the db by email
        const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
        //if user not found, throw error
        if(!user) {
            throw new ForbiddenException('Wrong email');
        }
        //if user found, compare password hash with password
        const match = await argon.verify(user.hash, dto.password);
        //if password does not match, throw error
        if(!match) {
            throw new ForbiddenException('Wrong password');
        }
        //if password matches, return user
        delete user.hash;
        return user;
    }
}