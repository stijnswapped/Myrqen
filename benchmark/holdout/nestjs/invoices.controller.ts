import { Controller, Get, NotFoundException, Param, Query, Req, UseGuards } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";
import { PdfService } from "../documents/pdf.service";
import { Invoice } from "./invoice.entity";

interface RequestWithUser {
  user: { id: string; organizationId: string; role: "member" | "manager" | "billing_admin" };
}

const PAGE_SIZE = 50;

@UseGuards(JwtAuthGuard)
@Controller("billing/invoices")
export class InvoicesController {
  constructor(
    @InjectRepository(Invoice) private readonly invoices: Repository<Invoice>,
    private readonly pdf: PdfService
  ) {}

  @Get()
  async list(@Req() req: RequestWithUser, @Query("cursor") cursor?: string) {
    return this.invoices.find({
      where: { organizationId: req.user.organizationId },
      order: { issuedAt: "DESC" },
      take: PAGE_SIZE,
      skip: cursor ? Number(cursor) : 0
    });
  }

  @Get(":id")
  async findOne(@Req() req: RequestWithUser, @Param("id") id: string) {
    const invoice = await this.invoices.findOne({
      where: { id, organizationId: req.user.organizationId }
    });
    if (!invoice) throw new NotFoundException("invoice not found");
    return invoice;
  }

  @Get(":id/document")
  async document(@Req() req: RequestWithUser, @Param("id") id: string) {
    const actorRole = req.user.role;
    const invoice = await this.invoices.findOne({
      where: { id },
      relations: { lines: true, organization: true }
    });
    if (!invoice) throw new NotFoundException("invoice not found");

    const rendered = await this.pdf.render(invoice, {
      watermark: actorRole === "billing_admin" ? null : "COPY",
      includeBankDetails: actorRole === "billing_admin"
    });
    return {
      filename: `${invoice.number}.pdf`,
      contentType: "application/pdf",
      contentBase64: rendered.toString("base64")
    };
  }
}
