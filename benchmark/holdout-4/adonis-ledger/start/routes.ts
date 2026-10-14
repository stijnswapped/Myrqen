/*
|--------------------------------------------------------------------------
| Ledger service HTTP surface
|--------------------------------------------------------------------------
|
| Everything an operator touches sits behind the session auth guard. The two
| bank callbacks are unauthenticated by design and verify their own payload
| signatures instead.
|
*/
import router from '@adonisjs/core/services/router'
import { middleware } from '#start/kernel'

const StatementsController = () => import('#controllers/statements_controller')
const LedgerExportsController = () => import('#controllers/ledger_exports_controller')
const InvoicesController = () => import('#controllers/invoices_controller')
const CreditNotesController = () => import('#controllers/credit_notes_controller')
const RemittancesController = () => import('#controllers/remittances_controller')
const SupplierDocumentsController = () => import('#controllers/supplier_documents_controller')
const TeamMemberSettingsController = () => import('#controllers/team_member_settings_controller')
const MemberProfileController = () => import('#controllers/member_profile_controller')
const StatementImportsController = () => import('#controllers/statement_imports_controller')
const BankFeedImportsController = () => import('#controllers/bank_feed_imports_controller')
const BankCallbacksController = () => import('#controllers/bank_callbacks_controller')
const CardSettlementCallbacksController = () => import('#controllers/card_settlement_callbacks_controller')

router
  .group(() => {
    router.get('/api/suppliers/:reference/statement', [StatementsController, 'show'])
    router.get('/api/suppliers/:reference/ledger-export', [LedgerExportsController, 'show'])
    router.get('/api/invoices', [InvoicesController, 'index'])
    router.get('/api/invoices/:id', [InvoicesController, 'show'])
    router.get('/api/credit-notes/:id', [CreditNotesController, 'show'])
    router.get('/api/remittances/:reference/document', [RemittancesController, 'document'])
    router.get('/api/supplier-documents/:id/download', [SupplierDocumentsController, 'download'])
    router.patch('/api/team-members/me/settings', [TeamMemberSettingsController, 'update'])
    router.patch('/api/team-members/me/profile', [MemberProfileController, 'update'])
    router.post('/api/statement-imports', [StatementImportsController, 'store'])
    router.post('/api/bank-feed-imports', [BankFeedImportsController, 'store'])
  })
  .use(middleware.auth())

router.post('/api/bank-callbacks/northbank', [BankCallbacksController, 'store'])
router.post('/api/card-callbacks/settlement', [CardSettlementCallbacksController, 'store'])
