import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { compare } from "bcryptjs";
import { prisma } from "@/lib/prisma";

export type Role = "owner" | "admin" | "editor" | "viewer";

export interface Session {
  user: { id: string; email: string; name: string | null };
}

export interface Membership {
  workspaceId: string;
  userId: string;
  role: Role;
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  session: { strategy: "jwt", maxAge: 60 * 60 * 8 },
  pages: { signIn: "/login" },
  providers: [
    Credentials({
      credentials: { email: {}, password: {} },
      async authorize(raw) {
        const email = String(raw?.email ?? "").trim().toLowerCase();
        const password = String(raw?.password ?? "");
        if (!email || password.length < 8) return null;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user?.passwordHash) return null;

        const matches = await compare(password, user.passwordHash);
        if (!matches) return null;

        return { id: user.id, email: user.email, name: user.name };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user?.id) token.sub = user.id;
      return token;
    },
    async session({ session, token }) {
      if (session.user && token.sub) {
        (session.user as { id?: string }).id = token.sub;
      }
      return session;
    },
  },
});

/** Throws UNAUTHENTICATED when there is no signed-in user; callers map that to a 401. */
export async function requireSession(): Promise<Session> {
  const session = (await auth()) as Session | null;
  if (!session?.user?.id) {
    throw new Error("UNAUTHENTICATED");
  }
  return session;
}

/** The caller's membership row for a workspace, or null when they are not a member. */
export async function getMembership(userId: string, workspaceId: string): Promise<Membership | null> {
  if (!workspaceId) return null;
  const member = await prisma.workspaceMember.findUnique({
    where: { workspaceId_userId: { workspaceId, userId } },
    select: { workspaceId: true, userId: true, role: true },
  });
  return member as Membership | null;
}

export async function requireMembership(userId: string, workspaceId: string): Promise<Membership> {
  const member = await getMembership(userId, workspaceId);
  if (!member) {
    throw new Error("FORBIDDEN");
  }
  return member;
}

export const ROLE_RANK: Record<Role, number> = { viewer: 0, editor: 1, admin: 2, owner: 3 };

export function isAtLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}
