// Sign-in page script. Pages that need a session send the visitor here with
// ?next=<where they were going>, and the form sends them back after signing in,
// as long as that is a page on this site.

const form = document.querySelector("#sign-in");
const errorBox = document.querySelector("#sign-in-error");

function returnPath() {
  const next = new URLSearchParams(window.location.search).get("next") ?? "/dashboard";
  const target = new URL(next, window.location.origin);
  if (target.origin !== window.location.origin) return "/dashboard";
  return target.pathname + target.search;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;

  const response = await fetch("/api/session", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email: form.elements.email.value,
      password: form.elements.password.value,
    }),
    credentials: "same-origin",
  });

  if (!response.ok) {
    errorBox.textContent = "Email or password is incorrect.";
    errorBox.hidden = false;
    return;
  }

  window.location.href = returnPath();
});
