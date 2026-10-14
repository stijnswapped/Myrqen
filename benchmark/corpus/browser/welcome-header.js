// Landing page script for invitation links. The invite email links to
// /join#<inviter name>, and the page greets the visitor by who invited them
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

  const heading = document.createElement("h2");
  heading.textContent = `${inviter} invited you`;
  const prompt = document.createElement("p");
  prompt.textContent = "Create your account to join them.";
  banner.replaceChildren(heading, prompt);
  banner.classList.add("is-personal");
}

document.addEventListener("DOMContentLoaded", renderGreeting);
window.addEventListener("hashchange", renderGreeting);
