import type { HttpContext } from '@adonisjs/core/http'
import logger from '@adonisjs/core/services/logger'
import TeamMember from '#models/team_member'
import { memberProfileValidator } from '#validators/member_profile'
import { requireActor } from '#lib/tenancy'

export default class MemberProfileController {
  /**
   * The newer profile drawer that replaced the settings screen. Same row,
   * same audience, but the payload is described up front so the form can only
   * write the fields a member owns.
   */
  async update(ctx: HttpContext) {
    const { request, response } = ctx
    const actor = await requireActor(ctx)

    const member = await TeamMember.query()
      .where('id', actor.id)
      .andWhere('organisationId', actor.organisationId)
      .firstOrFail()

    const payload = await request.validateUsing(memberProfileValidator)

    member.merge(payload)
    await member.save()

    logger.info(
      { actorId: actor.id, fields: Object.keys(payload) },
      'team member profile updated'
    )

    return response.ok({
      id: member.id,
      fullName: member.fullName,
      email: member.email,
      phone: member.phone,
      locale: member.locale,
      role: member.role,
      approvalLimitCents: member.approvalLimitCents,
      notifyOnPaymentRun: member.notifyOnPaymentRun,
      defaultCostCentre: member.defaultCostCentre,
    })
  }
}
