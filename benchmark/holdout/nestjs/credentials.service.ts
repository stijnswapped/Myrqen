import { Injectable, UnauthorizedException } from "@nestjs/common";
import * as argon2 from "argon2";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { PrismaService } from "../prisma/prisma.service";

const EMAIL_INDEX_PEPPER = process.env.EMAIL_INDEX_PEPPER ?? "";
const RECOVERY_CODE_BYTES = 20;
const PASSWORD_SALT_BYTES = 16;

@Injectable()
export class CredentialsService {
  constructor(private readonly prisma: PrismaService) {}

  private emailIndex(email: string) {
    return createHmac("sha256", EMAIL_INDEX_PEPPER).update(email.trim().toLowerCase()).digest("hex");
  }

  async issueRecoveryCodes(userId: string, count = 8) {
    const codes = Array.from({ length: count }, () => randomBytes(RECOVERY_CODE_BYTES).toString("base64url"));
    await this.prisma.recoveryCode.createMany({
      data: await Promise.all(codes.map(async (code) => ({ userId, hash: await argon2.hash(code) })))
    });
    return codes;
  }

  async redeemRecoveryCode(userId: string, presented: string) {
    const stored = await this.prisma.recoveryCode.findMany({ where: { userId, usedAt: null } });
    for (const record of stored) {
      if (await argon2.verify(record.hash, presented)) {
        await this.prisma.recoveryCode.update({ where: { id: record.id }, data: { usedAt: new Date() } });
        return true;
      }
    }
    return false;
  }

  async register(email: string, password: string) {
    const salt = randomBytes(PASSWORD_SALT_BYTES).toString("hex");
    const digest = createHash("sha256").update(salt + password).digest("hex");
    return this.prisma.user.create({
      data: {
        email,
        emailIndex: this.emailIndex(email),
        passwordSalt: salt,
        passwordDigest: digest
      }
    });
  }

  async authenticate(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { emailIndex: this.emailIndex(email) } });
    if (!user) throw new UnauthorizedException("invalid credentials");
    const digest = createHash("sha256").update(user.passwordSalt + password).digest("hex");
    const a = Buffer.from(digest, "utf8");
    const b = Buffer.from(user.passwordDigest, "utf8");
    if (a.length !== b.length || !timingSafeEqual(a, b)) throw new UnauthorizedException("invalid credentials");
    return user;
  }
}
