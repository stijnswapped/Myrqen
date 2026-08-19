import { BRAND } from "@myrqen/brand";
import { detachBinding, resolveRepositoryBinding } from "@myrqen/policy";
import { resolveClient } from "../api/client.js";
import { discoverProject, findRepoRoot } from "../discovery/project.js";
import { resolveBinding } from "../session/binding.js";
import { blank, bullet, field, heading, json, style, warn, write } from "../ui/output.js";
import { confirm } from "../ui/prompt.js";

export interface WorkspaceOptions {
  asJson?: boolean;
  set?: string;
  detach?: boolean;
}

/**
 * Shows and changes the repository binding, always stating the consequence of a
 * change before making it.
 */
export async function workspaceCommand(options: WorkspaceOptions = {}): Promise<void> {
  const repoRoot = await findRepoRoot(process.cwd());
  const { client, account } = await resolveClient();
  const existing = await resolveRepositoryBinding(repoRoot).catch((error) => {
    warn(error instanceof Error ? error.message : "The binding file could not be read.");
    return null;
  });

  if (options.detach) {
    if (!existing) {
      write("This repository is not bound, so there is nothing to detach.");
      return;
    }
    write(
      existing.source === "team_committed"
        ? `Detaching removes the committed ${BRAND.repoStateDirectoryName}/project.json binding. Other clones keep their copy until you commit the removal.`
        : "Detaching removes only your local binding. Nothing changes for anyone else."
    );
    const confirmed = await confirm("Detach this repository from its workspace?");
    if (!confirmed) {
      write("Left unchanged.");
      return;
    }
    const removed = await detachBinding(repoRoot, existing.source === "team_committed" ? "team" : "personal");
    for (const file of removed) bullet(`removed ${file}`);
    return;
  }

  if (options.set) {
    if (existing) {
      write(
        existing.source === "team_committed"
          ? `This repository has a committed team binding to workspace ${existing.workspaceId}. Detach it first with "${BRAND.cliName} workspace --detach" if you really want to move it.`
          : `This repository is bound to your personal workspace. Rebinding will replace the local binding.`
      );
      if (existing.source === "team_committed") return;
      const confirmed = await confirm("Replace the local binding?");
      if (!confirmed) return;
      await detachBinding(repoRoot, "personal");
    }
    const discovered = await discoverProject(repoRoot);
    const outcome = await resolveBinding(repoRoot, discovered.name, client, { workspaceId: options.set });
    if (outcome.bindingSource === "unbound") {
      warn(outcome.message ?? "The workspace could not be bound.");
      return;
    }
    write(`${style.ok("Bound")} ${outcome.workspaceName ?? outcome.workspaceId} (${outcome.workspaceKind})`);
    return;
  }

  heading("workspace");
  field("Repository", repoRoot);
  if (existing) {
    field(
      "Binding",
      `${existing.workspaceKind} workspace ${existing.workspaceId} · project ${existing.projectId} · ${
        existing.source === "team_committed" ? "committed file (safe to commit, contains no credentials)" : "local file (excluded from Git)"
      }`
    );
  } else {
    field("Binding", "none. The next scan will ask where this project belongs.");
  }

  if (client.authenticated && account) {
    try {
      const { workspaces } = await client.workspaces();
      blank();
      write(style.bold("Available workspaces"));
      for (const workspace of workspaces) {
        bullet(`${workspace.id}  ${workspace.name} (${workspace.kind}, plan ${workspace.plan})`);
      }
      blank();
      write(`Change with "${BRAND.cliName} workspace --set <workspace-id>" or detach with --detach.`);
      if (options.asJson) json({ repoRoot, binding: existing, workspaces });
      return;
    } catch (error) {
      warn(`Workspaces could not be listed: ${error instanceof Error ? error.message : "network error"}`);
    }
  } else {
    blank();
    write(`This device is not linked, so only local scans are available. Run "${BRAND.cliName} link" to change that.`);
  }
  if (options.asJson) json({ repoRoot, binding: existing, workspaces: [] });
}
