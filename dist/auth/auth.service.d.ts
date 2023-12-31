import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto/auth.dto";
export declare class AuthService {
    private prisma;
    constructor(prisma: PrismaService);
    signup(dto: AuthDto): Promise<{
        id: number;
        createdAt: Date;
        updatedAt: Date;
        email: string;
        hash: string;
        firstName: string;
        lastName: string;
    }>;
    signin(dto: AuthDto): Promise<{
        id: number;
        createdAt: Date;
        updatedAt: Date;
        email: string;
        hash: string;
        firstName: string;
        lastName: string;
    }>;
}
