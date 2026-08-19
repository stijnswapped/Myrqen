import crypto from "node:crypto";
import type { WorkspaceSummary } from "@myrqen/contracts";
import { bindingInteraction, resolveRepositoryBinding, writePersonalBinding, writeTeamBinding } from "@myrqen/policy";
import type { ResolvedBinding } from "@myrqen/policy";
import { ApiClient } from "../api/client.js";
import { choose, isInteractive } from "../ui/prompt.js";
import { blank, bullet, field, write } from "../ui/output.js";

export interface BindingOutcome {
  bindingSource: "team_committed" | "personal_local" | "unbound";
  workspaceId?: string;
  workspaceKind: "personal" | "team";
  workspaceName?: string;
  projectId?: string;
  needsChoice?: boolean;
  options?: WorkspaceSummary[];
  message?: string;
}

function bindingPublicId(): string {
  return `bnd_${crypto.randomBytes(16).toString("base64url")}`;
}

/**
 * Resolves the repository binding, creating a project only after an explicit
 * workspace choice. A personal repository never silently enters a team
 * workspace, and a team-bound clone never silently falls back to Personal.
 */
export async function resolveBinding(
  repoRoot: string,
  projectName: string,
  client: ApiClient | null,
  options: { workspaceId?: string } = {}
): Promise<BindingOutcome> {
  const existing = await resolveRepositoryBinding(repoRoot);
  if (existing) return await describeExisting(existing, client);

  if (!client?.authenticated) {
    return {
      bindingSource: "unbound",
      workspaceKind: "personal",
      message: "This repository is not bound to a workspace, and this device is not linked, so the scan stays local."
    };
  }

  const { workspaces } = await client.workspaces();
  if (workspaces.length === 0) {
    return {
      bindingSource: "unbound",
      workspaceKind: "personal",
      message: "No workspace is available for this account."
    };
  }

  let chosen: WorkspaceSummary | undefined;
  if (options.workspaceId) {
    chosen = workspaces.find((workspace) => workspace.id === options.workspaceId);
    if (!chosen) {
      return {
        bindingSource: "unbound",
        workspaceKind: "personal",
        message: `Workspace ${options.workspaceId} is not available to this account.`
      };
    }
  } else {
    const interaction = bindingInteraction({
      workspaces: workspaces.map((workspace) => ({ id: workspace.id, name: workspace.name, kind: workspace.kind })),
      repositoryHasTeamBinding: false
    });

    if (interaction.mode === "single_option") {
      chosen = workspaces[0];
    } else if (isInteractive()) {
      blank();
      const index = await choose(
        "Choose where this project belongs:",
        workspaces.map((workspace) => `${workspace.name} (${workspace.kind})`)
      );
      if (index === null) {
        return {
          bindingSource: "unbound",
          workspaceKind: "personal",
          message: "No workspace was chosen, so this scan stays local and unbound."
        };
      }
      chosen = workspaces[index];
    } else {
      return {
        bindingSource: "unbound",
        workspaceKind: "personal",
        needsChoice: true,
        options: workspaces,
        message:
          "This repository is not bound yet and several workspaces are available. Ask the user which workspace this project belongs to, then re-run with --workspace <id>."
      };
    }
  }

  if (!chosen) {
    return { bindingSource: "unbound", workspaceKind: "personal", message: "No workspace was chosen." };
  }

  const publicId = bindingPublicId();
  const created = await client.createProject({
    workspaceId: chosen.id,
    name: projectName,
    bindingPublicId: publicId
  });

  if (chosen.kind === "team") {
    await writeTeamBinding(repoRoot, { workspaceId: chosen.id, projectId: created.projectId });
  } else {
    await writePersonalBinding(repoRoot, {
      workspaceId: chosen.id,
      projectId: created.projectId,
      workspaceName: chosen.name,
      projectName
    });
  }

  return {
    bindingSource: chosen.kind === "team" ? "team_committed" : "personal_local",
    workspaceId: chosen.id,
    workspaceKind: chosen.kind,
    workspaceName: chosen.name,
    projectId: created.projectId
  };
}

async function describeExisting(binding: ResolvedBinding, client: ApiClient | null): Promise<BindingOutcome> {
  let workspaceName = binding.workspaceName;
  if (!workspaceName && client?.authenticated) {
    try {
      const { workspaces } = await client.workspaces();
      workspaceName = workspaces.find((workspace) => workspace.id === binding.workspaceId)?.name;
    } catch {
      // Metadata lookup is best-effort; the binding itself is authoritative.
    }
  }
  return {
    bindingSource: binding.source,
    workspaceId: binding.workspaceId,
    workspaceKind: binding.workspaceKind,
    ...(workspaceName ? { workspaceName } : {}),
    projectId: binding.projectId
  };
}

export function printBinding(outcome: BindingOutcome): void {
  if (outcome.bindingSource === "unbound") {
    field("Workspace", "not bound");
    if (outcome.message) bullet(outcome.message);
    if (outcome.options) {
      for (const workspace of outcome.options) write(`    ${workspace.id}  ${workspace.name} (${workspace.kind})`);
    }
    return;
  }
  field(
    "Workspace",
    `${outcome.workspaceName ?? outcome.workspaceId} (${outcome.workspaceKind}, ${
      outcome.bindingSource === "team_committed" ? "committed binding" : "local binding"
    })`
  );
}
