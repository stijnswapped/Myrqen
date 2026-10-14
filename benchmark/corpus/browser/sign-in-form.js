// Sign-in page script. Pages that need a session send the visitor here with
// ?next=<where they were going>, and the form sends them back after signing in.

const form = document.querySelector("#sign-in");
const errorBox = document.querySelector("#sign-in-error");

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

  const next = new URLSearchParams(window.location.search).get("next");
  window.location.href = next || "/dashboard";
});
