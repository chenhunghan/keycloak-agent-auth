# Changelog

## [0.4.0](https://github.com/chenhunghan/keycloak-agent-auth/compare/keycloak-agent-auth-v0.3.1...keycloak-agent-auth-v0.4.0) (2026-04-26)


### Features

* **admin:** add host link/unlink endpoints (AAP §2.9, §2.10, §3.2) ([78760f6](https://github.com/chenhunghan/keycloak-agent-auth/commit/78760f6c3f96375e4351003161e8383d3154e520))
* **admin:** add host pre-registration admin endpoints ([331ccaa](https://github.com/chenhunghan/keycloak-agent-auth/commit/331ccaabccfe075a8113bf1ac48371959286713f))
* **admin:** list endpoint for org-managed agent environments ([7d8876c](https://github.com/chenhunghan/keycloak-agent-auth/commit/7d8876ca0ecbe8691fdb774c594f38c1ad03bf90))
* **admin:** org-scoped SA-host pre-registration ([1171d20](https://github.com/chenhunghan/keycloak-agent-auth/commit/1171d20032686a06705b0441474402f760edfd2e))
* **admin:** org-self-serve agent environments ([9592c77](https://github.com/chenhunghan/keycloak-agent-auth/commit/9592c77cb42a6ea0e0f1c38f789a9f5ad830fc09))
* **admin:** Phase 5 multi-tenant — org-admin self-service + SA-as-host ([cf1d5c5](https://github.com/chenhunghan/keycloak-agent-auth/commit/cf1d5c53bbb250598cd0f5f735374b349374fdfd))
* **agent:** propagate host.user_id to new delegated agents (AAP §3.2) ([0a799a2](https://github.com/chenhunghan/keycloak-agent-auth/commit/0a799a23976b5df00f8fa99cd33e255e87734c69))
* **approval:** CIBA approval method + in-Keycloak inbox (§7.2) ([7da3b72](https://github.com/chenhunghan/keycloak-agent-auth/commit/7da3b726f6b8a4eec08b0c984265fe49f011dea7))
* **approval:** CIBA for capability-request + reactivate on linked hosts ([fa37283](https://github.com/chenhunghan/keycloak-agent-auth/commit/fa372832d5a6bcf871dfd0ebac5be6723f0bcbb9))
* **approval:** CIBA push delivery via Keycloak email (§7.2) ([ff29bbd](https://github.com/chenhunghan/keycloak-agent-auth/commit/ff29bbdae8652a7b2215b9dcbc44c856ad22d48e))
* **approval:** device-authorization approval for delegated registration ([8319939](https://github.com/chenhunghan/keycloak-agent-auth/commit/8319939b6968d83dcc0d1c0469f266edaadd37c0))
* **approval:** HTML verification page for device-authorization (§5.3, §7.1) ([3e0153c](https://github.com/chenhunghan/keycloak-agent-auth/commit/3e0153cf9248ee5d53bc46ca9560af0ecd5e7006))
* **approval:** partial per-capability approval (§5.3) ([959d9e9](https://github.com/chenhunghan/keycloak-agent-auth/commit/959d9e9c09a462d78754a8eb2194e4bb26404521))
* **approval:** per-host default_capabilities TOFU per AAP §3.1 + §5.3 ([65ce8f7](https://github.com/chenhunghan/keycloak-agent-auth/commit/65ce8f732b7fc35fa4d3d1476355e134aede1b32))
* **approval:** proof-of-presence gate for write-capable grants (§8.11) ([94eb0f0](https://github.com/chenhunghan/keycloak-agent-auth/commit/94eb0f0318378bd4d3e6669b4ca6a61621bcabfc))
* **approval:** sweep stale pending agents (AAP §7.1) ([43b7cb7](https://github.com/chenhunghan/keycloak-agent-auth/commit/43b7cb7cd7283a14fc9949fc7c8f7ce9f5a53aa7))
* **approval:** unify device_auth across all approval paths (§5.4, §5.6) ([8a47075](https://github.com/chenhunghan/keycloak-agent-auth/commit/8a47075db9345e32b095a3c3f62bc1ce99d197f3))
* **authz:** Phase 1 multi-tenant — cap schema + listing filter ([2a904a6](https://github.com/chenhunghan/keycloak-agent-auth/commit/2a904a6e66a3a53a549bdaa07a412659e3cfc813))
* **authz:** Phase 2 multi-tenant — approval-time + introspect-time enforcement ([9791b81](https://github.com/chenhunghan/keycloak-agent-auth/commit/9791b8145363113763bf741ed4102e3a6e86ed3e))
* **authz:** Phase 4 multi-tenant — eager cascade on org-membership leave ([7d2631b](https://github.com/chenhunghan/keycloak-agent-auth/commit/7d2631b3f2c7d8458ff69f682253617dd35553b4))
* **capability:** verify host+jwt sigs and filter by host defaults (§5.2) ([5dc6adf](https://github.com/chenhunghan/keycloak-agent-auth/commit/5dc6adf0da0ec7327bf54e4b8976149ef95d5ca3))
* **cleanup:** cascade pending-host GC alongside pending-agent sweep ([817a54d](https://github.com/chenhunghan/keycloak-agent-auth/commit/817a54dec15a864d04e2386684e43aa85e30f9d9))
* **examples:** add Python, Go, and Rust client examples ([a181412](https://github.com/chenhunghan/keycloak-agent-auth/commit/a181412e3fe9a22388f796d84116cb831609bd14))
* **examples:** add TypeScript walk-through under examples/js ([aaf0abe](https://github.com/chenhunghan/keycloak-agent-auth/commit/aaf0abefc1c90e55cfb98c51ee2e2866dd37ca3a))
* **register:** pending host state on dynamic registration per §2.8 + §2.11 ([37b9636](https://github.com/chenhunghan/keycloak-agent-auth/commit/37b963654d89dc7203384c1b924bd77de940419b))
* **register:** reject mode=delegated under SA-backed hosts ([afd31d2](https://github.com/chenhunghan/keycloak-agent-auth/commit/afd31d2f9574fa608e758bfd5fb7aa4b1e41fcf3))
* **storage:** add JpaStorage and make it the default backend ([58d0381](https://github.com/chenhunghan/keycloak-agent-auth/commit/58d03815a3ffb258b1a985fdc3ba2388ed408cf8))
* **storage:** cascade revocation on Keycloak user deletion (AAP §2.6) ([8f2d7c5](https://github.com/chenhunghan/keycloak-agent-auth/commit/8f2d7c512bb765e5594db083efc4934004bee5bb))
* **storage:** Phase 3 multi-tenant — AGENT_AUTH_AGENT_GRANT secondary index ([27a526c](https://github.com/chenhunghan/keycloak-agent-auth/commit/27a526c5a95b5ff806363bbb3305657193729fd0))
* **storage:** register JPA entities + Liquibase changelog via SPI ([01f1ba7](https://github.com/chenhunghan/keycloak-agent-auth/commit/01f1ba7bd93a6816ceb5c8be584983a29e782cdd))
* **verify:** redirect cookie-less browsers through KC login (§7.1) ([3480bd5](https://github.com/chenhunghan/keycloak-agent-auth/commit/3480bd56b9d8b503ef7b726022f0ea4bbd325531))
* **verify:** zero-CSS HTML, accessibility, CSRF on browser flow ([6b5d2ba](https://github.com/chenhunghan/keycloak-agent-auth/commit/6b5d2ba53572879c7cc79a328e2ef00ef9bca877))


### Bug Fixes

* **admin:** record approving admin's user id in granted_by ([5cd3ad7](https://github.com/chenhunghan/keycloak-agent-auth/commit/5cd3ad76920312b8abf3a65d4dabde27d971cfd2))
* **approval:** enforce user_code expiry at verifyApprove ([7934a87](https://github.com/chenhunghan/keycloak-agent-auth/commit/7934a8715ecbb36108e112164bfcafbc543cfbed))
* **authz:** close entitlement-gate gap at register/request/execute ([a9ba9ea](https://github.com/chenhunghan/keycloak-agent-auth/commit/a9ba9eab91efa85f25b8fdb662384ceed09490a4))
* **docker:** bundle nimbus/tink runtime libs into the image ([7ac6775](https://github.com/chenhunghan/keycloak-agent-auth/commit/7ac677580a1ae6aa87da3dd24657e6855ebf33c1))
* **docs:** quote Mermaid edge labels that contain parens ([ad51e77](https://github.com/chenhunghan/keycloak-agent-auth/commit/ad51e773c3b3d8e029b07a8ba8cbc040ee3022fe))
* **examples:** clear mypy + clippy lint complaints ([a5c50cc](https://github.com/chenhunghan/keycloak-agent-auth/commit/a5c50ccbe382c911a242fee25db5b81c508e5b5e))
* **execute:** require aud = resolved capability location per §4.3 ([7671694](https://github.com/chenhunghan/keycloak-agent-auth/commit/7671694c82c16e0064ebed3db8b546c1eb22d30f))
* fix the gaps between spec/test/impl ([db8b05e](https://github.com/chenhunghan/keycloak-agent-auth/commit/db8b05ed572e6283d73e34cd4ea837e235ef6f42))
* **gateway:** fall through to next upstream candidate on DNS miss ([c67fd7b](https://github.com/chenhunghan/keycloak-agent-auth/commit/c67fd7bb853533cefdff282918d2478916e89127))
* **introspect:** require aud = resolved capability location per §4.3 ([e98dd04](https://github.com/chenhunghan/keycloak-agent-auth/commit/e98dd04424dd78f3469a8f7547b07f1b798908bc))
* **notify:** throttle CIBA approval emails per (realm × user × agent) ([c7d8608](https://github.com/chenhunghan/keycloak-agent-auth/commit/c7d860806a74771cce5fa6784465bf7b88eaadc1))
* update test suites and fix the gaps in impl ([b4f3c57](https://github.com/chenhunghan/keycloak-agent-auth/commit/b4f3c574e82b66eb557d2d7f15d44cb03493759c))


### Documentation

* add architecture doc; expand README with actor table ([6528cf3](https://github.com/chenhunghan/keycloak-agent-auth/commit/6528cf31a2056c8cc35e498cb8f7cb5a82114d66))
* add TODO.md tracking the JSON-blob → typed-columns migration ([e2146d0](https://github.com/chenhunghan/keycloak-agent-auth/commit/e2146d0b8224a02b979fab2ca9dd8e4a3279e320))
* align README endpoint table with current source ([7adca4e](https://github.com/chenhunghan/keycloak-agent-auth/commit/7adca4eaf623d29ea038462c1d43622a165c9fc9))
* **architecture:** align host/agent JWT aud bullet with §4.3 ([0cbaa32](https://github.com/chenhunghan/keycloak-agent-auth/commit/0cbaa32e8781a313cbb7282e4d01bcb907f493fb))
* **architecture:** link AAP-coined terms to spec; drop verbatim quotes ([9d50789](https://github.com/chenhunghan/keycloak-agent-auth/commit/9d50789b1f229e6fd6819189eb946f73c2f3ee84))
* clarify CIBA is post-link channel, not missing linking trigger ([af606dc](https://github.com/chenhunghan/keycloak-agent-auth/commit/af606dc50fe8ad80ae8433c79d00e8120e4d42d1))
* correct device-flow implementation status ([8bf90a2](https://github.com/chenhunghan/keycloak-agent-auth/commit/8bf90a2627db8c8c068997999fcda933ccdcca7b))
* migrate diagrams to Mermaid; document host linking (§2.9/§2.10/§3.2) ([e088d67](https://github.com/chenhunghan/keycloak-agent-auth/commit/e088d6712adbcc059dbd2abc5b9cfaf0e3b4218a))
* **readme:** dissolve "Protocol reference" section into natural homes ([a0b4d03](https://github.com/chenhunghan/keycloak-agent-auth/commit/a0b4d0330050322c86a57ac00c72f723d1a90740))
* **readme:** drop spec-paraphrased Role column from Protocol-actors table ([dc8507f](https://github.com/chenhunghan/keycloak-agent-auth/commit/dc8507fccc68512cbefb66018e6260472bc3f8b7))
* **readme:** hoist multi-tenancy as a top-of-readme value-prop callout ([950e880](https://github.com/chenhunghan/keycloak-agent-auth/commit/950e880864ce10b22ca102d29b54b212c3029f0b))
* **readme:** link "Keycloak Organizations" to Keycloak's docs ([9931154](https://github.com/chenhunghan/keycloak-agent-auth/commit/99311546d56e26400918987a9be9b3862f6cdb93))
* **readme:** link AAP-coined terms to their canonical spec sections ([0eece21](https://github.com/chenhunghan/keycloak-agent-auth/commit/0eece21a243576a9071d1fe482d80ff5c284a35c))
* **readme:** link every §X.Y citation to the spec website anchor ([5755e4d](https://github.com/chenhunghan/keycloak-agent-auth/commit/5755e4d211fd7519a5a48bb8925a450624ece910))
* **readme:** note pending-host cascade in cleanup endpoint row ([c565f6b](https://github.com/chenhunghan/keycloak-agent-auth/commit/c565f6b24f6113788936273580f4c561ffcdf068))
* **readme:** regroup endpoint tables by caller; add base-URL preamble ([87c2843](https://github.com/chenhunghan/keycloak-agent-auth/commit/87c2843cc6b2e74d11e960454488701cb74d1016))
* **readme:** rewrite Multi-tenant scoping by caller; add orgs-disabled footnote ([9eca868](https://github.com/chenhunghan/keycloak-agent-auth/commit/9eca868e8065cd7bab4fa1734c8fed50a5df6296))
* **readme:** tighten "Why Keycloak?" intro ([3480828](https://github.com/chenhunghan/keycloak-agent-auth/commit/348082824d32d9ef0d62c74cc5af7e902bf622f6))
* **readme:** tighten Architecture intro after the diagram ([a39017d](https://github.com/chenhunghan/keycloak-agent-auth/commit/a39017d0a7da66d90487f780c1c66876ea7c637a))
* **readme:** tighten Architecture/Execution sections; drop "Hybrid model" label ([677ed92](https://github.com/chenhunghan/keycloak-agent-auth/commit/677ed9229bf1e03890205a7e7f3104eeaca4ff6c))
* simplify architecture.md flowcharts; leave sequences as-is ([697fdab](https://github.com/chenhunghan/keycloak-agent-auth/commit/697fdab84a94aed8e72aa9eb4b9a2a03bf6bc963))
* simplify README diagrams to pure topology ([7721158](https://github.com/chenhunghan/keycloak-agent-auth/commit/7721158bc4c0d0f4d10c6ef65ca36287b6690864))
* split Agent and Client in README hybrid-model diagram ([df1e310](https://github.com/chenhunghan/keycloak-agent-auth/commit/df1e31092d1dfe0bd0c01b2936ae59b1241b96d2))
* tighten architecture.md Mermaid diagrams ([9273eea](https://github.com/chenhunghan/keycloak-agent-auth/commit/9273eea72a74c890834278ff664e1fbfaf98f437))
* **todo:** add §5.2 capability-listing gaps ([d218cd0](https://github.com/chenhunghan/keycloak-agent-auth/commit/d218cd01eecfe972d22871cf8951dd92f19351f6))
* **todo:** add multi-tenancy section — Organizations-scoped capability registry ([3c32273](https://github.com/chenhunghan/keycloak-agent-auth/commit/3c322739dbb655132ce52a3608e7559aacd8f681))
* **todo:** demote multi-tenancy to a design draft with explicit open questions ([0c04bf7](https://github.com/chenhunghan/keycloak-agent-auth/commit/0c04bf75c4c7e47a8e54c906d9ea9b7517192bc3))
* **todo:** promote authz draft into a committed multi-tenant plan ([8ca7cc8](https://github.com/chenhunghan/keycloak-agent-auth/commit/8ca7cc8b1dca32e440a86ad5a2bbb76b8faddb2c))
* update README + architecture for the session's multi-tenant + storage work ([591b1d2](https://github.com/chenhunghan/keycloak-agent-auth/commit/591b1d216ac13a6cbbcf9c447ea07050ef4f4408))

## [0.3.1](https://github.com/chenhunghan/keycloak-agent-auth/compare/keycloak-agent-auth-v0.3.0...keycloak-agent-auth-v0.3.1) (2026-04-05)


### Bug Fixes

* fix ci build error ([3dde74c](https://github.com/chenhunghan/keycloak-agent-auth/commit/3dde74ccc0dd3be9b7818e9ba791f66bdf8e3a90))

## [0.3.0](https://github.com/chenhunghan/keycloak-agent-auth/compare/keycloak-agent-auth-v0.2.1...keycloak-agent-auth-v0.3.0) (2026-04-05)


### Features

* add cache header for discovery endpoint ([125cb28](https://github.com/chenhunghan/keycloak-agent-auth/commit/125cb289e3027ed47b726ac94030e06a4ce91f03))
* initial Keycloak Agent Auth Protocol extension ([588dd76](https://github.com/chenhunghan/keycloak-agent-auth/commit/588dd76eeb2949ef3b5830a92240536946a55592))


### Bug Fixes

* fix release pipeline ([02cc487](https://github.com/chenhunghan/keycloak-agent-auth/commit/02cc487cbd668e56801f7bf9c5e342c02eff5c42))
* stabilize host rotation and integration tests ([6913ff7](https://github.com/chenhunghan/keycloak-agent-auth/commit/6913ff78197d1ca1f89294a35cf12e490ed05115))


### Documentation

* note release asset verification ([89db94f](https://github.com/chenhunghan/keycloak-agent-auth/commit/89db94f33d99246421f0734ffb32b5cf0c243bbb))
* note release automation ([a1033ac](https://github.com/chenhunghan/keycloak-agent-auth/commit/a1033ac294e13f191da103ad5ad35cf4538f278c))

## [0.2.1](https://github.com/chenhunghan/keycloak-agent-auth/compare/keycloak-agent-auth-v0.2.0...keycloak-agent-auth-v0.2.1) (2026-04-05)


### Documentation

* note release automation ([a1033ac](https://github.com/chenhunghan/keycloak-agent-auth/commit/a1033ac294e13f191da103ad5ad35cf4538f278c))

## [0.2.0](https://github.com/chenhunghan/keycloak-agent-auth/compare/keycloak-agent-auth-v0.1.0...keycloak-agent-auth-v0.2.0) (2026-04-05)


### Features

* add cache header for discovery endpoint ([125cb28](https://github.com/chenhunghan/keycloak-agent-auth/commit/125cb289e3027ed47b726ac94030e06a4ce91f03))
* initial Keycloak Agent Auth Protocol extension ([588dd76](https://github.com/chenhunghan/keycloak-agent-auth/commit/588dd76eeb2949ef3b5830a92240536946a55592))


### Bug Fixes

* stabilize host rotation and integration tests ([6913ff7](https://github.com/chenhunghan/keycloak-agent-auth/commit/6913ff78197d1ca1f89294a35cf12e490ed05115))
