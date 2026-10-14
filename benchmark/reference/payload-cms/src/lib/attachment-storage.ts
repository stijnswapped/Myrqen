import path from 'node:path'

/**
 * Root of the generated-document store. The nightly export worker writes
 * statement PDFs and reconciliation CSVs to `<root>/<tenantId>/<name>`, so a
 * tenant's files never share a directory with another tenant's.
 */
export const ATTACHMENT_ROOT = path.resolve(process.env.ATTACHMENT_ROOT ?? './var/attachments')

const CONTENT_TYPES: Record<string, string> = {
  '.csv': 'text/csv; charset=utf-8',
  '.json': 'application/json',
  '.pdf': 'application/pdf',
  '.txt': 'text/plain; charset=utf-8',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.zip': 'application/zip',
}

export const contentTypeFor = (name: string): string =>
  CONTENT_TYPES[path.extname(name).toLowerCase()] ?? 'application/octet-stream'

/** Raised when a storage key would resolve outside the tenant's own folder. */
export class StorageKeyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'StorageKeyError'
  }
}

/**
 * Turn a stored key into an absolute path inside the tenant's own folder.
 *
 * `path.resolve` collapses any `.` and `..` segments first, so the containment
 * comparison below is done on the final location rather than on the text the
 * caller handed us. Anything that ends up outside the folder is refused instead
 * of clamped, so a bad key surfaces as an error rather than as someone else's
 * document.
 */
export const resolveWithinTenantStore = (tenantId: string, key: string): string => {
  const base = path.resolve(ATTACHMENT_ROOT, tenantId)
  const target = path.resolve(base, key)

  if (target !== base && !target.startsWith(base + path.sep)) {
    throw new StorageKeyError(`Storage key "${key}" resolves outside the store for tenant ${tenantId}.`)
  }

  return target
}

/** Human-facing size, used in the export listing screen. */
export const formatBytes = (bytes: number): string => {
  if (bytes < 1024) {
    return `${bytes} B`
  }
  const units = ['KB', 'MB', 'GB']
  let value = bytes / 1024
  let unitIndex = 0
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024
    unitIndex += 1
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`
}
