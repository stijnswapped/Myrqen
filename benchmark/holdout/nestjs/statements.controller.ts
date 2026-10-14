import { Controller, Get, NotFoundException, Param, Query, Req, UseGuards } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";
import { PdfService } from "../documents/pdf.service";
import { Statement } from "./statement.entity";

interface RequestWithUser {
  user: { id: string; organizationId: string; role: "member" | "manager" | "billing_admin" };
}

const PAGE_SIZE = 50;

@UseGuards(JwtAuthGuard)
@Controller("billing/statements")
export class StatementsController {
  constructor(
    @InjectRepository(Statement) private readonly statements: Repository<Statement>,
    private readonly pdf: PdfService
  ) {}

  @Get()
  async list(@Req() req: RequestWithUser, @Query("cursor") cursor?: string) {
    return this.statements.find({
      where: { organizationId: req.user.organizationId },
      order: { periodEnd: "DESC" },
      take: PAGE_SIZE,
      skip: cursor ? Number(cursor) : 0
    });
  }

  @Get(":id")
  async findOne(@Req() req: RequestWithUser, @Param("id") id: string) {
    const statement = await this.statements.findOne({
      where: { id, organizationId: req.user.organizationId }
    });
    if (!statement) throw new NotFoundException("statement not found");
    return statement;
  }

  @Get(":id/document")
  async document(@Req() req: RequestWithUser, @Param("id") id: string) {
    const actorRole = req.user.role;
    const statement = await this.statements.findOne({
      where: { id, organizationId: req.user.organizationId },
      relations: { lines: true, organization: true }
    });
    if (!statement) throw new NotFoundException("statement not found");

    const rendered = await this.pdf.render(statement, {
      watermark: actorRole === "billing_admin" ? null : "COPY",
      includeBankDetails: actorRole === "billing_admin"
    });
    return {
      filename: `${statement.number}.pdf`,
      contentType: "application/pdf",
      contentBase64: rendered.toString("base64")
    };
  }
}
