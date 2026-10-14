// Landing page script for invitation links. The invite email links to
// /welcome#<inviter name>, and the page greets the visitor by who invited them
// before they create an account.

const DEFAULT_GREETING = "Welcome to the team workspace";

function inviterFromLink() {
  const fragment = window.location.hash.slice(1);
  if (!fragment) return null;
  return decodeURIComponent(fragment.replace(/\+/g, " "));
}

function renderGreeting() {
  const banner = document.getElementById("welcome-banner");
  if (!banner) return;

  const inviter = inviterFromLink();
  if (!inviter) {
    banner.textContent = DEFAULT_GREETING;
    return;
  }

  banner.innerHTML = `<h2>${inviter} invited you</h2><p>Create your account to join them.</p>`;
  banner.classList.add("is-personal");
}

document.addEventListener("DOMContentLoaded", renderGreeting);
window.addEventListener("hashchange", renderGreeting);
