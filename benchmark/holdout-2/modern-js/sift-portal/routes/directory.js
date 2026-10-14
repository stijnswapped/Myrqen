import { entities, layout, quoteAttr } from "../lib/markup.js";
import { listPeople } from "../lib/index-store.js";

export const method = "GET";
export const path = "/directory";

const MAX_TEAM_LENGTH = 120;
const PAGE_SIZE = 20;

function personItem(person) {
  return `<li class="person">
    <a href=${quoteAttr(`/directory/${person.handle}`)}>${entities(person.name)}</a>
    <p class="role">${entities(person.role)}</p>
    <span class="team">${entities(person.team)}</span>
  </li>`;
}

export async function handler({ query, html }) {
  const team = (query.get("team") ?? "").trim().slice(0, MAX_TEAM_LENGTH);
  const page = Math.max(1, Number.parseInt(query.get("page") ?? "1", 10) || 1);

  const people = await listPeople({ team: team || null, page, pageSize: PAGE_SIZE });

  const results =
    people.length > 0
      ? `<ul class="people">${people.map(personItem).join("")}</ul>`
      : `<p class="empty">Nobody is listed under <strong>${entities(team)}</strong>. Try another team.</p>`;

  const body = `
    <h1>Staff directory</h1>
    <form class="search" method="get" action="/directory">
      <input type="search" name="team" value=${quoteAttr(team)} placeholder="Filter by team">
      <button type="submit">Filter</button>
    </form>
    ${results}
    ${people.length === PAGE_SIZE ? `<a class="more" href=${quoteAttr(`/directory?team=${encodeURIComponent(team)}&page=${page + 1}`)}>Next page</a>` : ""}
  `;

  return html(layout("Staff directory", body));
}
