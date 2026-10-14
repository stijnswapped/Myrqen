import { Service } from "encore.dev/service";

// Owns organizations, users, memberships and sessions. Every other service
// hangs off the ids this one hands out.
export default new Service("identity");
