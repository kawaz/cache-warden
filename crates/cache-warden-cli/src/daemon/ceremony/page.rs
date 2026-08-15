//! The ceremony page, embedded in the binary (DR-0034 §10).
//!
//! Serving the page from the daemon rather than from static hosting is a
//! decision DR-0032 made and DR-0034 §10 restates: a host that serves this
//! page can replace its script, and a compromised page can take the PRF output
//! it is holding. Keeping it in the binary means the only way to change it is
//! to change the binary — which is already the trust anchor.
//!
//! # What the script is not allowed to do
//!
//! The PRF output is the vault's key material in the clear. For the moment it
//! exists in the page, the script:
//!
//! - never writes it to the DOM, `console`, `localStorage`, `sessionStorage`,
//!   or any URL;
//! - posts it once and drops its only reference;
//! - runs under a content security policy that permits no external script, no
//!   inline handler, and no connection to any host but this one — so even a
//!   script injected some other way has nowhere to send it.
//!
//! The policy is `default-src 'none'`, which starts from "nothing is allowed"
//! and adds back the two things this page needs: its own script, identified by
//! a per-response nonce, and `connect-src 'self'` for the four endpoints.

use rand_core::RngCore as _;

/// A per-response CSP nonce.
///
/// Regenerated for every request rather than fixed at build time: a nonce an
/// attacker can predict is a nonce they can write an inline script against,
/// which is the whole thing the nonce is there to prevent.
pub fn nonce() -> String {
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The `Content-Security-Policy` header value for a given nonce.
pub fn csp(nonce: &str) -> String {
    format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; \
         connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
}

/// The page itself, with `nonce` substituted into its script and style tags.
pub fn html(nonce: &str) -> String {
    PAGE.replace("{{nonce}}", nonce)
}

const PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>cache-warden vault</title>
<style nonce="{{nonce}}">
  :root { color-scheme: light dark; }
  body {
    font: 16px/1.5 system-ui, sans-serif;
    max-width: 34rem; margin: 4rem auto; padding: 0 1.5rem;
  }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  p.sub { margin-top: 0; opacity: .75; }
  button {
    font: inherit; padding: .6rem 1.2rem; border-radius: .5rem;
    border: 1px solid currentColor; background: transparent; cursor: pointer;
  }
  button[disabled] { opacity: .5; cursor: default; }
  #status { margin-top: 1.5rem; min-height: 3rem; }
  .ok { color: #157f3d; }
  .fail { color: #b3261e; }
</style>
</head>
<body>
<h1>cache-warden vault</h1>
<p class="sub" id="intent">Preparing&hellip;</p>
<button id="go" disabled>Continue</button>
<div id="status" role="status" aria-live="polite"></div>
<script nonce="{{nonce}}">
(() => {
  "use strict";
  const statusEl = document.getElementById("status");
  const intentEl = document.getElementById("intent");
  const button = document.getElementById("go");

  const say = (text, cls) => {
    statusEl.textContent = text;
    statusEl.className = cls || "";
  };

  const b64urlToBytes = (s) => {
    const padded = s.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(padded + "===".slice((padded.length + 3) % 4));
    return Uint8Array.from(raw, (c) => c.charCodeAt(0));
  };
  const bytesToB64url = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const post = async (path, payload) => {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload || {}),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || ("request failed: " + res.status));
    return body;
  };

  // The server describes what this page is for; the page does not choose.
  let mode = null;
  const start = async () => {
    const info = await post("/begin", {});
    mode = info.mode;
    intentEl.textContent =
      mode === "register"
        ? "Register this passkey as a way to unlock the vault."
        : "Unlock the vault with a registered passkey.";
    button.disabled = false;
    say("Ready when you are.");
    return info;
  };

  const register = async (info) => {
    const options = info.options.publicKey;
    options.challenge = b64urlToBytes(options.challenge);
    options.user.id = b64urlToBytes(options.user.id);

    const credential = await navigator.credentials.create({ publicKey: options });
    const prf = credential.getClientExtensionResults().prf;
    if (!prf || !prf.enabled) {
      throw new Error(
        "this passkey cannot derive keys (no PRF support), so it cannot open the vault"
      );
    }
    // Registration only establishes that the credential *can* do PRF. The
    // value itself comes from an assertion, which is the same path a later
    // unlock takes — so a passkey that registers is one that can unlock.
    const evaluated = await evaluatePrf(info.salt, credential.rawId);

    await post("/register/finish", {
      credential_id: bytesToB64url(credential.rawId),
      client_data_json: bytesToB64url(credential.response.clientDataJSON),
      attestation_object: bytesToB64url(credential.response.attestationObject),
      prf_output: bytesToB64url(evaluated),
    });
  };

  // Run an assertion whose only purpose is to evaluate the PRF for `salt`.
  const evaluatePrf = async (salt, rawId) => {
    const step = await post("/register/evaluate", {
      credential_id: bytesToB64url(rawId),
    });
    const options = step.options.publicKey;
    options.challenge = b64urlToBytes(options.challenge);
    options.allowCredentials = [{ type: "public-key", id: b64urlToBytes(salt.credential_id) }];
    options.extensions = { prf: { eval: { first: b64urlToBytes(salt.first) } } };

    const assertion = await navigator.credentials.get({ publicKey: options });
    const results = assertion.getClientExtensionResults().prf;
    if (!results || !results.results || !results.results.first) {
      throw new Error("the authenticator returned no PRF output");
    }
    return results.results.first;
  };

  const unlock = async (info) => {
    const options = info.options.publicKey;
    options.challenge = b64urlToBytes(options.challenge);
    options.allowCredentials = (options.allowCredentials || []).map((c) => ({
      type: "public-key",
      id: b64urlToBytes(c.id),
    }));
    // Per-credential salts: each slot has its own, so the authenticator is
    // told which to evaluate for whichever credential the user picks.
    const byCredential = {};
    for (const [id, first] of Object.entries(info.salts)) {
      byCredential[id] = { first: b64urlToBytes(first) };
    }
    options.extensions = { prf: { evalByCredential: byCredential } };

    const assertion = await navigator.credentials.get({ publicKey: options });
    const results = assertion.getClientExtensionResults().prf;
    if (!results || !results.results || !results.results.first) {
      throw new Error("the authenticator returned no PRF output");
    }
    // The output goes straight into the request body and the reference is
    // dropped with this scope. It is never held anywhere the page can be
    // asked for it again.
    await post("/unlock/finish", {
      credential_id: bytesToB64url(assertion.rawId),
      authenticator_data: bytesToB64url(assertion.response.authenticatorData),
      client_data_json: bytesToB64url(assertion.response.clientDataJSON),
      signature: bytesToB64url(assertion.response.signature),
      prf_output: bytesToB64url(results.results.first),
    });
  };

  button.addEventListener("click", async () => {
    button.disabled = true;
    say("Waiting for your passkey…");
    try {
      const info = await start();
      if (mode === "register") {
        await register(info);
        say("Passkey registered. You can close this page.", "ok");
      } else {
        await unlock(info);
        say("Vault unlocked. You can close this page.", "ok");
      }
    } catch (err) {
      // The message is shown; nothing derived from key material ever is.
      say(err && err.message ? err.message : "the ceremony did not complete", "fail");
      button.disabled = false;
    }
  });

  start().catch((err) => say(err.message || "could not start", "fail"));
})();
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_starts_from_nothing_and_names_what_it_allows() {
        let n = nonce();
        let policy = csp(&n);
        assert!(policy.starts_with("default-src 'none'"), "{policy}");
        assert!(
            policy.contains(&format!("script-src 'nonce-{n}'")),
            "{policy}"
        );
        assert!(policy.contains("connect-src 'self'"), "{policy}");
        // No escape hatches: any of these would let an injected script run or
        // reach a host of its choosing.
        for forbidden in ["unsafe-inline", "unsafe-eval", "*", "https:"] {
            assert!(
                !policy.contains(forbidden),
                "the policy must not contain {forbidden}: {policy}"
            );
        }
    }

    #[test]
    fn each_page_gets_a_fresh_unpredictable_nonce() {
        assert_ne!(nonce(), nonce());
        assert!(nonce().len() >= 20);
    }

    #[test]
    fn the_page_carries_the_nonce_on_every_script_and_style() {
        let n = nonce();
        let page = html(&n);
        assert!(
            !page.contains("{{nonce}}"),
            "every placeholder is substituted"
        );
        let tags = page.matches("<script").count() + page.matches("<style").count();
        let nonces = page.matches(&format!("nonce=\"{n}\"")).count();
        assert_eq!(tags, nonces, "a tag without the nonce would not run");
    }

    /// The script must not have anywhere to leave the PRF output behind.
    #[test]
    fn the_script_never_reaches_for_storage_or_the_console() {
        let page = html(&nonce());
        for forbidden in [
            "localStorage",
            "sessionStorage",
            "console.",
            "document.cookie",
            "indexedDB",
            "window.name",
        ] {
            assert!(
                !page.contains(forbidden),
                "the ceremony page must not use {forbidden}"
            );
        }
    }
}
