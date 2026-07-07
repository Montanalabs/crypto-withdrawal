#! VULNERABLE crypto-withdrawal — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant withdraw irreversible

let raw = fetch<web>
commit { withdraw(raw) }  # tainted -> tool: REJECTED
