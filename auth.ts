import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import postgres from 'postgres';
import bcrypt from 'bcrypt';
import type { User } from '@/app/lib/definitions';
const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string) {
    try {
        const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
        return user[0];
    } catch (error) {
        console.error('Failed to fetch user:', error);
        throw new Error('Failed to fetch user.');
    }
}

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [Credentials({
        async authorize(credentials, req) {
            const parsedCredentials = z
                .object({ email: z.string().email(), password: z.string().min(6) })
                .safeParse(credentials);
            if (parsedCredentials.success) {
                const { email, password } = parsedCredentials.data;
                const user = await getUser(email);
                if (!user) return null;

                const isPasswordValid = await bcrypt.compare(password, user.password);
                if (!isPasswordValid) return null;

                return user;
            }

            return null;
        },
    })
    ]
});