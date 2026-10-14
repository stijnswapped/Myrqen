/**
 * Nestlings — nursery and childcare management platform.
 *
 * Deployment surface for the whole backend. Everything a client can reach is
 * re-exported from here; nothing else in src/ is deployed.
 *
 * Regions: the guardian app and the educator tablets are both EU-only, and the
 * Firestore database lives in europe-west4, so all functions are pinned there to keep
 * reads in-region.
 */
import { setGlobalOptions } from "firebase-functions/v2";
import { initializeApp } from "firebase-admin/app";

initializeApp();

setGlobalOptions({
  region: "europe-west4",
  maxInstances: 20,
  timeoutSeconds: 60,
  memory: "512MiB",
});

// Enrollment
export { getChildProfile, listChildrenForGuardian } from "./enrollment/childProfiles";
export { getGuardianChildSummary } from "./enrollment/guardianAccess";
export { updateChildRecord } from "./enrollment/childRecordUpdates";

// Staff and access administration
export { assignStaffRole } from "./staff/roleAssignments";
export { inviteCentreMember } from "./staff/staffOnboarding";

// Daily room activity
export { submitDailyReport, onDailyReportWritten } from "./daily/dailyReportEntries";

// Billing
export { invoiceDocument } from "./billing/invoiceDelivery";
export { monthlyStatement } from "./billing/statementDelivery";
export { paymentProviderEvents } from "./billing/paymentWebhooks";
export { refundProviderEvents } from "./billing/refundNotifications";

// Outbound integrations
export { registerCentreWebhook } from "./integrations/parentPortalHooks";
export { configureMessagingProvider } from "./integrations/messagingProviders";
