import { DataTypes, Model, Sequelize } from 'sequelize';

/**
 * Requisition — the internal purchasing tool we run in Slack.
 *
 * Everything the listeners touch goes through Sequelize; there is no HTTP API in front
 * of the database and no ORM other than this one.
 */
const connectionUrl =
  process.env.DATABASE_URL ?? 'postgres://requisitions@localhost:5432/requisitions';

export const sequelize = new Sequelize(connectionUrl, {
  logging: process.env.SQL_ECHO === '1' ? (sql: string) => console.debug(sql) : false,
  define: { underscored: true, timestamps: true },
  pool: { max: 12, min: 1, idle: 10_000 },
});

/** Role somebody holds *in Requisition*. Nothing to do with their Slack workspace role. */
export type MemberRole = 'requester' | 'approver' | 'finance_admin';

export type RequisitionStatus =
  | 'draft'
  | 'submitted'
  | 'approved'
  | 'rejected'
  | 'closed'
  | 'void';

export class Installation extends Model {
  declare id: number;
  declare teamId: string;
  declare enterpriseId: string | null;
  declare botToken: string;
  declare installedBySlackUserId: string;
}

Installation.init(
  {
    teamId: { type: DataTypes.STRING(24), allowNull: false },
    enterpriseId: { type: DataTypes.STRING(24), allowNull: true },
    botToken: { type: DataTypes.TEXT, allowNull: false },
    installedBySlackUserId: { type: DataTypes.STRING(24), allowNull: false },
  },
  { sequelize, modelName: 'installation', tableName: 'installations' },
);

export class CostCenter extends Model {
  declare id: number;
  declare code: string;
  declare name: string;
  declare ownerSlackUserId: string;
}

CostCenter.init(
  {
    code: { type: DataTypes.STRING(16), allowNull: false, unique: true },
    name: { type: DataTypes.STRING(120), allowNull: false },
    ownerSlackUserId: { type: DataTypes.STRING(24), allowNull: false },
  },
  { sequelize, modelName: 'costCenter', tableName: 'cost_centers' },
);

export class Member extends Model {
  declare id: number;
  declare slackUserId: string;
  declare teamId: string;
  declare email: string;
  declare displayName: string;
  declare role: MemberRole;
  declare costCenterId: number;
  declare approvalLimitCents: number;
  declare digestHour: number;
  declare timezone: string;
  declare notifyChannelId: string | null;
  declare isActive: boolean;
}

Member.init(
  {
    slackUserId: { type: DataTypes.STRING(24), allowNull: false },
    teamId: { type: DataTypes.STRING(24), allowNull: false },
    email: { type: DataTypes.STRING(180), allowNull: false },
    displayName: { type: DataTypes.STRING(120), allowNull: false },
    role: {
      type: DataTypes.ENUM('requester', 'approver', 'finance_admin'),
      allowNull: false,
      defaultValue: 'requester',
    },
    costCenterId: { type: DataTypes.INTEGER, allowNull: false },
    approvalLimitCents: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    digestHour: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 9 },
    timezone: { type: DataTypes.STRING(64), allowNull: false, defaultValue: 'Europe/Dublin' },
    notifyChannelId: { type: DataTypes.STRING(24), allowNull: true },
    isActive: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
  },
  {
    sequelize,
    modelName: 'member',
    tableName: 'members',
    indexes: [{ unique: true, fields: ['slack_user_id', 'team_id'] }],
  },
);

export class Vendor extends Model {
  declare id: number;
  declare name: string;
  declare taxId: string;
  declare bankAccountLast4: string;
  declare contactEmail: string;
  /** What we actually negotiated. Commercially sensitive — not for general circulation. */
  declare negotiatedRateCents: number;
}

Vendor.init(
  {
    name: { type: DataTypes.STRING(160), allowNull: false },
    taxId: { type: DataTypes.STRING(32), allowNull: false },
    bankAccountLast4: { type: DataTypes.STRING(4), allowNull: false },
    contactEmail: { type: DataTypes.STRING(180), allowNull: false },
    negotiatedRateCents: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  },
  { sequelize, modelName: 'vendor', tableName: 'vendors' },
);

export class Requisition extends Model {
  declare id: number;
  declare reference: string;
  declare costCenterId: number;
  declare requesterSlackUserId: string;
  declare vendorId: number;
  declare amountCents: number;
  declare currency: string;
  declare status: RequisitionStatus;
  declare justification: string;
  declare contractPriceCents: number | null;
  declare approvedBySlackUserId: string | null;
}

Requisition.init(
  {
    reference: { type: DataTypes.STRING(16), allowNull: false, unique: true },
    costCenterId: { type: DataTypes.INTEGER, allowNull: false },
    requesterSlackUserId: { type: DataTypes.STRING(24), allowNull: false },
    vendorId: { type: DataTypes.INTEGER, allowNull: false },
    amountCents: { type: DataTypes.INTEGER, allowNull: false },
    currency: { type: DataTypes.STRING(3), allowNull: false, defaultValue: 'EUR' },
    status: {
      type: DataTypes.ENUM('draft', 'submitted', 'approved', 'rejected', 'closed', 'void'),
      allowNull: false,
      defaultValue: 'draft',
    },
    justification: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    contractPriceCents: { type: DataTypes.INTEGER, allowNull: true },
    approvedBySlackUserId: { type: DataTypes.STRING(24), allowNull: true },
  },
  { sequelize, modelName: 'requisition', tableName: 'requisitions' },
);

export class Budget extends Model {
  declare id: number;
  declare costCenterId: number;
  declare fiscalPeriod: string;
  declare allocatedCents: number;
  declare committedCents: number;
  declare ownerSlackUserId: string;
}

Budget.init(
  {
    costCenterId: { type: DataTypes.INTEGER, allowNull: false },
    fiscalPeriod: { type: DataTypes.STRING(8), allowNull: false },
    allocatedCents: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    committedCents: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    ownerSlackUserId: { type: DataTypes.STRING(24), allowNull: false },
  },
  { sequelize, modelName: 'budget', tableName: 'budgets' },
);

export class ApprovalEvent extends Model {
  declare id: number;
  declare requisitionId: number;
  declare actorSlackUserId: string;
  declare decision: 'approved' | 'rejected' | 'escalated' | 'closed' | 'void';
  declare note: string | null;
}

ApprovalEvent.init(
  {
    requisitionId: { type: DataTypes.INTEGER, allowNull: false },
    actorSlackUserId: { type: DataTypes.STRING(24), allowNull: false },
    decision: {
      type: DataTypes.ENUM('approved', 'rejected', 'escalated', 'closed', 'void'),
      allowNull: false,
    },
    note: { type: DataTypes.TEXT, allowNull: true },
  },
  { sequelize, modelName: 'approvalEvent', tableName: 'approval_events' },
);

Member.belongsTo(CostCenter, { foreignKey: 'costCenterId' });
Requisition.belongsTo(CostCenter, { foreignKey: 'costCenterId' });
Requisition.belongsTo(Vendor, { foreignKey: 'vendorId' });
Requisition.hasMany(ApprovalEvent, { foreignKey: 'requisitionId' });
ApprovalEvent.belongsTo(Requisition, { foreignKey: 'requisitionId' });
Budget.belongsTo(CostCenter, { foreignKey: 'costCenterId' });
