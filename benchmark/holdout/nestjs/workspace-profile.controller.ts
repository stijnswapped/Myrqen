import { Body, Controller, Get, Patch, Req, UseGuards } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";
import { WorkspaceMemberProfile } from "./workspace-member-profile.entity";

const PUBLIC_FIELDS = ["displayName", "locale", "timezone", "avatarUrl"] as const;

interface RequestWithUser {
  user: { id: string };
}

@UseGuards(JwtAuthGuard)
@Controller("me/workspace-profile")
export class WorkspaceProfileController {
  constructor(
    @InjectRepository(WorkspaceMemberProfile) private readonly profiles: Repository<WorkspaceMemberProfile>
  ) {}

  private present(profile: WorkspaceMemberProfile) {
    const view: Record<string, unknown> = { id: profile.id, email: profile.email };
    for (const field of PUBLIC_FIELDS) view[field] = profile[field];
    return view;
  }

  @Get()
  async read(@Req() req: RequestWithUser) {
    const profile = await this.profiles.findOneByOrFail({ userId: req.user.id });
    return this.present(profile);
  }

  @Patch("notifications")
  async notifications(@Req() req: RequestWithUser, @Body() body: { digest?: boolean; mentions?: boolean }) {
    const profile = await this.profiles.findOneByOrFail({ userId: req.user.id });
    if (typeof body.digest === "boolean") profile.notifyDigest = body.digest;
    if (typeof body.mentions === "boolean") profile.notifyMentions = body.mentions;
    await this.profiles.save(profile);
    return this.present(profile);
  }

  @Patch()
  async update(@Req() req: RequestWithUser, @Body() body: Partial<WorkspaceMemberProfile>) {
    const profile = await this.profiles.findOneByOrFail({ userId: req.user.id });
    for (const field of PUBLIC_FIELDS) {
      if (field in body) Object.assign(profile, { [field]: body[field] });
    }
    profile.updatedAt = new Date();
    const saved = await this.profiles.save(profile);
    return this.present(saved);
  }
}
