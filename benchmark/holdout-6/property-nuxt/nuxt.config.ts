// Harbourlet — property management portal.
//
// The Nuxt app itself lives in app/; everything security relevant is a Nitro
// server route under server/api. Runtime config is populated from the platform
// environment (NUXT_DATABASE_URL, NUXT_PORTAL_TOKEN_SECRET, ...).
export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  future: { compatibilityVersion: 4 },
  nitro: {
    experimental: { asyncContext: true },
  },
  runtimeConfig: {
    databaseUrl: '',
    databasePoolSize: '10',
    databaseCa: '',
    redisUrl: '',
    portalTokenSecret: '',
    portalTokenIssuer: 'https://auth.harbourlet.example',
    documentRoot: '/var/lib/harbourlet/documents',
    uploadRoot: '/var/lib/harbourlet/uploads',
    // Comma separated hosts our scheduling partners are allowed to expose.
    inspectionPartnerHosts: 'calendar.harbourlet.example,partners.harbourlet.example',
    public: {
      portalBaseUrl: 'https://portal.harbourlet.example',
      supportPhone: '+31 20 555 0123',
    },
  },
})
