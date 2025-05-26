import bcrypt from "bcryptjs";
import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import GitHub from "next-auth/providers/github";
import Google from "next-auth/providers/google";

import { IAccountDoc } from "./database/account.model";
import { IUserDoc } from "./database/user.model";
import { api } from "./lib/api";
import { SignInSchema } from "./lib/validations";
import { ActionResponse } from "./types/global";

// Simple ObjectId validation (24 hex chars)
function isValidObjectId(id?: string): boolean {
  return typeof id === "string" && /^[a-f\d]{24}$/i.test(id);
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    GitHub,
    Google,
    Credentials({
      async authorize(credentials) {
        const validationFields = SignInSchema.safeParse(credentials);

        if (validationFields.success) {
          const { email, password } = validationFields.data;

          const { data: existingAccount } = (await api.accounts.getByProvider(
            email
          )) as ActionResponse<IAccountDoc>;

          if (!existingAccount) return null;

          // Use simple validation instead of mongoose's isValidObjectId
          if (!isValidObjectId(existingAccount.userId?.toString())) {
            console.error("Invalid userId in existingAccount:", existingAccount.userId);
            return null;
          }

          const { data: existingUser } = (await api.users.getById(
            existingAccount.userId.toString()
          )) as ActionResponse<IUserDoc>;

          if (!existingUser) return null;

          const isValidPassword = await bcrypt.compare(
            password,
            existingAccount.password!
          );

          if (isValidPassword) {
            return {
              id: existingUser.id,
              name: existingUser.name,
              email: existingUser.email,
              image: existingUser.image,
            };
          }
        }

        return null;
      },
    }),
  ],
  callbacks: {
    async session({ session, token }) {
      session.user.id = token.sub as string;
      return session;
    },
    async jwt({ token, account }) {
      if (account) {
        const providerKey = account.type === "credentials" ? token.email! : account.providerAccountId;

        const { success, data: existingAccount } =
          (await api.accounts.getByProvider(providerKey)) as ActionResponse<IAccountDoc>;

        if (!success || !existingAccount) return token;

        if (!isValidObjectId(existingAccount.userId?.toString())) {
          console.error("Invalid userId in existingAccount:", existingAccount.userId);
          return token;
        }

        const userId = existingAccount.userId;
        if (userId) token.sub = userId.toString();
      }

      return token;
    },
    async signIn({ user, profile, account }) {
      if (account?.type === "credentials") return true;
      if (!account || !user) return false;

      // Allow OAuth sign-in without API call for now
      return true;
    },
  },
});
