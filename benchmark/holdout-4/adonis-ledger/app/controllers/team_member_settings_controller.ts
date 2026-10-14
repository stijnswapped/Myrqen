import type { HttpContext } from '@adonisjs/core/http'
import logger from '@adonisjs/core/services/logger'
import TeamMember from '#models/team_member'
import { requireActor } from '#lib/tenancy'

export default class TeamMemberSettingsController {
  /**
   * Self-service settings drawer. Clerks keep their own contact details,
   * notification preferences and default cost centre current here, so the
   * screen is open to every role.
   */
  async update(ctx: HttpContext) {
    const { request, response } = ctx
    const actor = await requireActor(ctx)

    const member = await TeamMember.query()
      .where('id', actor.id)
      .andWhere('organisationId', actor.organisationId)
      .firstOrFail()

    const submitted = request.all()

    // Only the keys the settings form actually submitted get touched, and the
    // query above pins the row to the caller, so nobody can edit a colleague
    // or reach outside their own organisation.
    member.merge(submitted)
    await member.save()

    logger.info(
      { actorId: actor.id, fields: Object.keys(submitted) },
      'team member settings updated'
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
