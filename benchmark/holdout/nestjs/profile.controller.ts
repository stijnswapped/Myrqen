import { Body, Controller, Get, Patch, Req, UseGuards } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";
import { UserAccount } from "./user-account.entity";

const PUBLIC_FIELDS = ["displayName", "locale", "timezone", "avatarUrl"] as const;

interface RequestWithUser {
  user: { id: string };
}

@UseGuards(JwtAuthGuard)
@Controller("me")
export class ProfileController {
  constructor(@InjectRepository(UserAccount) private readonly accounts: Repository<UserAccount>) {}

  private present(account: UserAccount) {
    const view: Record<string, unknown> = { id: account.id, email: account.email };
    for (const field of PUBLIC_FIELDS) view[field] = account[field];
    return view;
  }

  @Get()
  async read(@Req() req: RequestWithUser) {
    const account = await this.accounts.findOneByOrFail({ id: req.user.id });
    return this.present(account);
  }

  @Patch("notifications")
  async notifications(@Req() req: RequestWithUser, @Body() body: { digest?: boolean; mentions?: boolean }) {
    const account = await this.accounts.findOneByOrFail({ id: req.user.id });
    if (typeof body.digest === "boolean") account.notifyDigest = body.digest;
    if (typeof body.mentions === "boolean") account.notifyMentions = body.mentions;
    await this.accounts.save(account);
    return this.present(account);
  }

  @Patch()
  async update(@Req() req: RequestWithUser, @Body() body: Partial<UserAccount>) {
    const account = await this.accounts.findOneByOrFail({ id: req.user.id });
    Object.assign(account, body);
    account.updatedAt = new Date();
    const saved = await this.accounts.save(account);
    return this.present(saved);
  }
}
