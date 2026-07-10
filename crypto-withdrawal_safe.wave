#! Crypto-withdrawal guard — untrusted an address and amount can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires withdraw — the crypto-withdrawal guard sink
#! @effect io
#! @irreversible
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant withdraw irreversible

type Wallet = Cold | Hot | Vault
type Decision = Send(Wallet) | Reject

let raw = fetch<web>  # UNTRUSTED an address and amount — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
commit { withdraw(d) }  # act on the trusted decision only
