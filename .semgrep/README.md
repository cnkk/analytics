# Security rules

Static rules for the vulnerability classes that have actually been fixed in this
repository, so the next instance is caught in review instead of in a follow-up
PR. They are derived from ten real pull requests and replayed against each one —
see [`backtest/RESULTS.md`](backtest/RESULTS.md).

```sh
pip install semgrep
semgrep --config .semgrep/plausible-security.yaml lib assets/js tracker/src
```

## The two packs

| file | engine | verified |
| --- | --- | --- |
| `plausible-security.yaml` | Semgrep OSS, Semgrep Pro, Opengrep | yes — 90/90 back-test expectations |
| `plausible-security-elixir.yaml` | Opengrep or Semgrep **Pro** only | no — see below |

Semgrep OSS will not run Elixir. It is one of two Pro-gated languages (with
Apex), and a rule declaring `languages: [elixir]` is skipped outright — even one
whose only condition is a regex:

```
Warning: 5 rule(s) were skipped because they require Pro (try `--pro`)
 • Findings: 0
```

So the pack that CI runs expresses the Elixir checks in `generic` and `regex`
mode, which every engine supports. `generic` mode is token-based rather than
line-based and supports `pattern-inside` / `pattern-not-inside`, which is what
makes the router rule ("a `live` route not enclosed in a `live_session`")
possible without an Elixir parser.

`plausible-security-elixir.yaml` holds the same checks against the real AST.
Those rules are schema-valid and reviewed but **were never executed**, because
only Semgrep OSS was available where they were written. Point the back-test at
an Opengrep binary before putting them in CI:

```sh
SEMGREP_BIN=/path/to/opengrep python3 .semgrep/backtest/backtest.py
```

## Rules

| id | severity | catches | from |
| --- | --- | --- | --- |
| `plausible-ecto-cast-tenant-key` | ERROR | `cast/3` allow-list containing `:site_id`, `:team_id` or `:id` — the request can move a row between sites | [#6402](https://github.com/plausible/analytics/pull/6402) [#6388](https://github.com/plausible/analytics/pull/6388) [#6396](https://github.com/plausible/analytics/pull/6396) |
| `plausible-ecto-cast-foreign-key` | WARNING | `cast/3` of a cross-resource FK (`:segment_id`, `:goal_id`, …) that is never re-resolved inside the caller's scope | [#6449](https://github.com/plausible/analytics/pull/6449) |
| `plausible-ecto-cast-capability-token` | ERROR | `cast/3` of a bearer secret or immutable id (`:slug`, `:token`, `:api_key`) | [#6449](https://github.com/plausible/analytics/pull/6449) |
| `plausible-repo-lookup-missing-tenant-scope` | ERROR | a site-scoped schema fetched by a user-supplied key with no `site_id` in the query (IDOR) | [#6402](https://github.com/plausible/analytics/pull/6402) [#6388](https://github.com/plausible/analytics/pull/6388) |
| `plausible-oauth-state-unsigned` | ERROR | OAuth `state` built with `Jason.encode!` and trusted back via `Jason.decode!` instead of `Phoenix.Token` | [#6396](https://github.com/plausible/analytics/pull/6396) [#6388](https://github.com/plausible/analytics/pull/6388) |
| `plausible-elixir-html-interpolation` | ERROR | HTML assembled by Elixir `#{}` interpolation with no escaping — plain strings are not HEEx | [#5321](https://github.com/plausible/analytics/pull/5321) |
| `plausible-elixir-js-literal-interpolation` | ERROR | a JS object property hand-quoted around `#{}`, so an apostrophe closes the string | [#6386](https://github.com/plausible/analytics/pull/6386) |
| `plausible-js-innerhtml-unescaped-label` | ERROR | a user-controlled label interpolated into a template literal assigned to `innerHTML` | [#6181](https://github.com/plausible/analytics/pull/6181) |
| `plausible-liveview-route-missing-live-session` | WARNING | a `live` route whose only authorization is `pipe_through` — router plugs do not run on the WebSocket mount | [#6417](https://github.com/plausible/analytics/pull/6417) [#6646](https://github.com/plausible/analytics/pull/6646) |

## The four recurring shapes

Nine rules, but only four underlying mistakes:

**1. The owning scope arrives in the request.** `cast/3` is an allow-list, and
`:site_id` kept ending up on it. `%Schema{site_id: site.id}`, `put_change/3` and
`put_assoc/3` all set the scope from the struct the caller was already
authorized for; `cast/3` sets it from the request body.

**2. A record is fetched by user key without its scope.** `Repo.get_by(SharedLink,
slug: slug)` returns somebody else's link just as happily as your own. The scope
belongs in the query, not in a check afterwards.

**3. Data crosses a template boundary with the wrong escaping.** HEEx escapes;
a plain Elixir string does not, a JS string literal needs JS escaping rather
than HTML escaping, and a JS template literal assigned to `innerHTML` needs
escaping the language gives you no help with. Each boundary has its own rule
because each has its own correct answer — `html_escape/1`, `Jason.encode!/1`,
`escapeHTML(...)`.

**4. Authorization lives in a layer the request can skip.** Router plugs run for
the first HTTP render; LiveView's WebSocket `mount/3` and every subsequent
`handle_event/3` do not go through them. Same for OAuth `state`: it is checked
once on the way out and then trusted on the way back, having passed through the
user's browser in between. Both are fixed by re-checking where the privileged
work happens — `on_mount`, `Phoenix.Token.verify/4`.

## Tuning

Prefer fixing the rule over silencing the line. If a finding is genuinely fine,
`// nosemgrep: <rule-id>` (or `# nosemgrep: <rule-id>`) on the line above, with a
comment saying why.

After any rule change, re-run the back-test — it is what stops a rule from being
widened until it stops catching the bug it was written for:

```sh
python3 .semgrep/backtest/backtest.py
```

CI runs it automatically on pull requests that touch `.semgrep/`.
