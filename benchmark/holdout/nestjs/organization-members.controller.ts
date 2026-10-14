import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  NotFoundException,
  Param,
  Patch,
  Req,
  UseGuards
} from "@nestjs/common";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";
import { Roles } from "../auth/roles.decorator";
import { RolesGuard } from "../auth/roles.guard";
import { PrismaService } from "../prisma/prisma.service";

const RANK = { member: 0, manager: 1, admin: 2, owner: 3 } as const;
type Role = keyof typeof RANK;

interface RequestWithUser {
  user: { id: string; email: string };
}

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller("organizations/:orgId/members")
export class OrganizationMembersController {
  constructor(private readonly prisma: PrismaService) {}

  @Roles("admin", "owner")
  @Delete(":memberId")
  async remove(
    @Req() req: RequestWithUser,
    @Param("orgId") orgId: string,
    @Param("memberId") memberId: string
  ) {
    const requester = await this.prisma.membership.findFirst({
      where: { organizationId: orgId, userId: req.user.id }
    });
    if (!requester) throw new NotFoundException("membership not found");

    const target = await this.prisma.membership.findFirst({
      where: { organizationId: orgId, id: memberId }
    });
    if (!target) throw new NotFoundException("membership not found");
    if (RANK[requester.role as Role] <= RANK[target.role as Role]) {
      throw new ForbiddenException("cannot act on an equal or higher role");
    }

    await this.prisma.membership.delete({ where: { id: target.id } });
    return { removed: target.id };
  }

  @Patch(":memberId/role")
  async setRole(
    @Req() req: RequestWithUser,
    @Param("orgId") orgId: string,
    @Param("memberId") memberId: string,
    @Body() body: { role: Role }
  ) {
    if (!(body.role in RANK)) throw new ForbiddenException("unknown role");

    const requester = await this.prisma.membership.findFirst({
      where: { organizationId: orgId, userId: req.user.id }
    });
    if (!requester) throw new NotFoundException("membership not found");

    const target = await this.prisma.membership.findFirst({
      where: { organizationId: orgId, id: memberId }
    });
    if (!target) throw new NotFoundException("membership not found");

    const updated = await this.prisma.membership.update({
      where: { id: target.id },
      data: { role: body.role, roleChangedBy: requester.id, roleChangedAt: new Date() }
    });
    return { id: updated.id, role: updated.role };
  }
}
