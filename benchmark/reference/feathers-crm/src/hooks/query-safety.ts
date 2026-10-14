import { BadRequest } from '@feathersjs/errors'

/**
 * What a client is allowed to say in `params.query`.
 *
 * Feathers passes the query straight to the adapter, and the Mongo adapter understands `$`
 * operators, so an unfiltered query is a query language handed to the caller. The service's
 * `filters`/`operators` options are the supported way to bound that; these helpers are for
 * the places that assemble a query by hand.
 */

/** Operators this application uses. Anything else is refused rather than dropped. */
const ALLOWED_OPERATORS = new Set(['$in', '$nin', '$lt', '$lte', '$gt', '$gte', '$ne', '$sort', '$limit', '$skip'])

/**
 * Refuse a query carrying an operator we do not use.
 *
 * Refusing rather than stripping: a caller who sent `$where` asked for something, and
 * silently answering a different question is how an injection becomes a data leak nobody
 * notices. `$where` and `$function` execute server-side JavaScript; `$regex` is a denial of
 * service on an unindexed field.
 */
export function refuseUnknownOperators(value: unknown, path = 'query'): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => refuseUnknownOperators(entry, `${path}[${index}]`))
    return
  }
  if (value === null || typeof value !== 'object') {
    return
  }
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (key.startsWith('$') && !ALLOWED_OPERATORS.has(key)) {
      throw new BadRequest(`Unsupported query operator ${key} at ${path}.`)
    }
    refuseUnknownOperators(nested, `${path}.${key}`)
  }
}

/** Keep only the fields a client may set, so an unexpected one cannot reach the adapter. */
export function pickFields<T extends Record<string, unknown>>(data: T, allowed: readonly string[]): Partial<T> {
  const out: Partial<T> = {}
  for (const field of allowed) {
    if (Object.prototype.hasOwnProperty.call(data, field)) {
      out[field as keyof T] = data[field as keyof T]
    }
  }
  return out
}
