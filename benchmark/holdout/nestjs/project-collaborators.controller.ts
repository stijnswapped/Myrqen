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
@Controller("projects/:projectId/collaborators")
export class ProjectCollaboratorsController {
  constructor(private readonly prisma: PrismaService) {}

  @Roles("admin", "owner")
  @Delete(":collaboratorId")
  async remove(
    @Req() req: RequestWithUser,
    @Param("projectId") projectId: string,
    @Param("collaboratorId") collaboratorId: string
  ) {
    const requester = await this.prisma.collaboration.findFirst({
      where: { projectId, userId: req.user.id }
    });
    if (!requester) throw new NotFoundException("collaboration not found");

    const target = await this.prisma.collaboration.findFirst({
      where: { projectId, id: collaboratorId }
    });
    if (!target) throw new NotFoundException("collaboration not found");
    if (RANK[requester.role as Role] <= RANK[target.role as Role]) {
      throw new ForbiddenException("cannot act on an equal or higher role");
    }

    await this.prisma.collaboration.delete({ where: { id: target.id } });
    return { removed: target.id };
  }

  @Roles("admin", "owner")
  @Patch(":collaboratorId/role")
  async setRole(
    @Req() req: RequestWithUser,
    @Param("projectId") projectId: string,
    @Param("collaboratorId") collaboratorId: string,
    @Body() body: { role: Role }
  ) {
    if (!(body.role in RANK)) throw new ForbiddenException("unknown role");

    const requester = await this.prisma.collaboration.findFirst({
      where: { projectId, userId: req.user.id }
    });
    if (!requester) throw new NotFoundException("collaboration not found");

    const target = await this.prisma.collaboration.findFirst({
      where: { projectId, id: collaboratorId }
    });
    if (!target) throw new NotFoundException("collaboration not found");
    if (RANK[requester.role as Role] <= RANK[target.role as Role]) {
      throw new ForbiddenException("cannot act on an equal or higher role");
    }
    if (RANK[body.role] >= RANK[requester.role as Role]) {
      throw new ForbiddenException("cannot grant a role at or above your own");
    }

    const updated = await this.prisma.collaboration.update({
      where: { id: target.id },
      data: { role: body.role, roleChangedBy: requester.id, roleChangedAt: new Date() }
    });
    return { id: updated.id, role: updated.role };
  }
}
