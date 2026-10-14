import { Injectable, UnauthorizedException } from "@nestjs/common";
import * as argon2 from "argon2";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { PrismaService } from "../prisma/prisma.service";

const EMAIL_INDEX_PEPPER = process.env.EMAIL_INDEX_PEPPER ?? "";
const RECOVERY_CODE_BYTES = 20;
const ARGON_OPTIONS = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

@Injectable()
export class OperatorCredentialsService {
  constructor(private readonly prisma: PrismaService) {}

  private emailIndex(email: string) {
    return createHmac("sha256", EMAIL_INDEX_PEPPER).update(email.trim().toLowerCase()).digest("hex");
  }

  private avatarKey(email: string) {
    return createHash("sha256").update(email.trim().toLowerCase()).digest("hex");
  }

  async issueRecoveryCodes(userId: string, count = 8) {
    const codes = Array.from({ length: count }, () => randomBytes(RECOVERY_CODE_BYTES).toString("base64url"));
    await this.prisma.operatorRecoveryCode.createMany({
      data: await Promise.all(codes.map(async (code) => ({ userId, hash: await argon2.hash(code, ARGON_OPTIONS) })))
    });
    return codes;
  }

  async redeemRecoveryCode(userId: string, presented: string) {
    const stored = await this.prisma.operatorRecoveryCode.findMany({ where: { userId, usedAt: null } });
    for (const record of stored) {
      if (await argon2.verify(record.hash, presented)) {
        await this.prisma.operatorRecoveryCode.update({ where: { id: record.id }, data: { usedAt: new Date() } });
        return true;
      }
    }
    return false;
  }

  async register(email: string, password: string) {
    const digest = await argon2.hash(password, ARGON_OPTIONS);
    return this.prisma.operator.create({
      data: {
        email,
        emailIndex: this.emailIndex(email),
        avatarKey: this.avatarKey(email),
        passwordDigest: digest
      }
    });
  }

  async authenticate(email: string, password: string) {
    const user = await this.prisma.operator.findUnique({ where: { emailIndex: this.emailIndex(email) } });
    if (!user) throw new UnauthorizedException("invalid credentials");
    if (!(await argon2.verify(user.passwordDigest, password))) {
      throw new UnauthorizedException("invalid credentials");
    }
    return user;
  }
}
