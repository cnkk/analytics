# Back-test results

Every rule in `.semgrep/plausible-security.yaml` was replayed against the ten
pull requests it was derived from. Reproduce with:

```sh
pip install semgrep
python3 .semgrep/backtest/backtest.py
```

## Method

For each PR the harness builds two trees:

| tree | contents |
| --- | --- |
| `after` | the PR's head commit, as merged |
| `before` | the same head with the PR's own diff **reverse-applied** |

Reverse-applying the PR onto its own head is the load-bearing detail. Several of
these branches were cut from an older `master`, so `git diff base...head` drags
in hundreds of unrelated files and the "before" tree stops being the code the PR
actually changed — `#6417`'s base-diff touches 630 files for a 2-file change.
Reverse-applying isolates exactly the PR's own edit.

Findings are then keyed by **the source line they sit on**, not by line number.
A PR that adds a `@moduledoc` shifts every line below it, and comparing line
numbers reports untouched code as "fixed" — an earlier iteration of this harness
did exactly that and scored `#6388` as catching five things it had not caught.
Matched text alone does not work either: `generic` mode reports only the leading
token of a match, so all twelve `live` routes in `router.ex` come back as the
same four bytes.

Each rule is judged **only on the files the PR touched**, taken from the patch.

## Scoring

- **detects** — the rule must fire on the PR's changed files before the fix, and
  its finding count on those files must drop after it.
- **silent** — the rule must not fire on those files in either tree. Each of
  these PRs fixes exactly one vulnerability class, so every rule aimed at a
  different class has to stay quiet on the same code. This is what stops a rule
  from being widened until it matches everything and still "passes".

## Results

90 of 90 expectations met (10 PRs × 9 rules).

| PR | fix | rule | before → after |
| --- | --- | --- | --- |
| [#5321](https://github.com/plausible/analytics/pull/5321) | escape team name in CRM | `elixir-html-interpolation` | 20 → 18 |
| [#6181](https://github.com/plausible/analytics/pull/6181) | escape goal name in funnel tooltip | `js-innerhtml-unescaped-label` | 2 → 0 |
| [#6386](https://github.com/plausible/analytics/pull/6386) | escape goal fields in Alpine `x-data` | `elixir-js-literal-interpolation` | 3 → 0 |
| [#6388](https://github.com/plausible/analytics/pull/6388) | cross-tenant changesets (closed draft) | `ecto-cast-tenant-key` | 7 → 0 |
| | | `repo-lookup-missing-tenant-scope` | 1 → 0 |
| | | `oauth-state-unsigned` | 4 → 0 |
| | | `elixir-js-literal-interpolation` | 3 → 0 |
| [#6396](https://github.com/plausible/analytics/pull/6396) | Google OAuth callbacks | `ecto-cast-tenant-key` | 1 → 0 |
| | | `oauth-state-unsigned` | 4 → 0 |
| [#6402](https://github.com/plausible/analytics/pull/6402) | params → structs during provisioning | `ecto-cast-tenant-key` | 7 → 0 |
| | | `repo-lookup-missing-tenant-scope` | 1 → 0 |
| [#6417](https://github.com/plausible/analytics/pull/6417) | super-admin `on_mount` for `/cs`, `/flags` | `liveview-route-missing-live-session` | 12 → 8 |
| [#6449](https://github.com/plausible/analytics/pull/6449) | shared-link segment scoping + immutable slug | `ecto-cast-capability-token` | 1 → 0 |
| | | `ecto-cast-foreign-key` | 1 → 0 |
| [#6646](https://github.com/plausible/analytics/pull/6646) | `DISABLE_REGISTRATION` in LiveView | `liveview-route-missing-live-session` | 6 → 4 |
| [#6638](https://github.com/plausible/analytics/pull/6638) | `DISABLE_REGISTRATION` (closed) | — no rule scores it — | see below |

The residual counts are not misses. `#6417` leaves 8 because `router.ex` has
other `live` routes outside a `live_session` (below); `#5321` leaves 18 because
the 2025 CRM built most of its markup this way and the PR escaped two of them.
In both cases the rule went quiet on precisely the lines the PR changed:

```
── PR #6417
   PASS plausible-liveview-route-missing-live-session: 12 before -> 8 after
          caught router.ex: live "/cs", CustomerSupport, :index, as: :customer_support
          caught router.ex: live "/cs/sites/site/:id", CustomerSupport.Site, :show, …
          caught router.ex: live "/cs/teams/team/:id", CustomerSupport.Team, :show, …
          caught router.ex: live "/cs/users/user/:id", CustomerSupport.User, :show, …
```

## What #6638 shows

`#6638` is the one PR no rule scores, and that is the useful result.

It and `#6646` fix the same bug: `DISABLE_REGISTRATION` was enforced by a router
plug, which LiveView does not run on the WebSocket mount, so registration stayed
reachable. `#6638` re-checked the flag inside the `handle_event/3` handlers.
`#6646` moved the routes into a `live_session` with an `on_mount` hook — and was
the one that merged, with `#6638` closed behind it.

The ruleset is silent across `#6638`'s entire diff, because that diff never
touches `router.ex`, and the router is the only place this class is visible to a
file-local rule. A static rule can see "this route has no `on_mount`"; it cannot
see "this handler forgot a check that the equivalent plug performs". So the
detector agrees with the maintainers' own conclusion: guarding handlers
one-by-one is not a fix a reviewer can verify, and moving the route is.

`plausible-liveview-handle-event-unguarded-write-ast` in the Elixir pack is the
nearest approximation of the handler-level check, at LOW confidence.

## Regression check on current `master`

13 findings, all reviewed:

| finding | verdict |
| --- | --- |
| `site/traffic_change_notification.ex:21` casts `:site_id` | **real** — `SiteController.update_traffic_change_notification/2` passes raw `params` straight into this changeset, so `site_id` is settable by the request |
| `site/weekly_report.ex:14`, `site/monthly_report.ex:14` cast `:site_id` | unsafe by construction; today's callers happen to pass a server-built map |
| `site/tracker_script_configuration.ex:43,60` cast `:site_id` | needs review — reached via `PlausibleWeb.Tracker` with a `config_update` map |
| `plugins/api/token.ex:48` casts `:site_id` | weak — a following `put_assoc(:site, site)` wins, but the field should not be castable |
| `clickhouse_event_v2.ex:63` casts `:site_id` | low risk — ingestion schema, not a user-params changeset |
| `router.ex` ×5: `/sites`, `/team/setup`, `/:domain/installation`, `/:domain/change-domain{,/success}` | real instances of the `#6417` class, guarded only by `RequireAccountPlug` in the pipeline |
| `stats_controller.ex:268` `Repo.get_by(SharedLink, slug: slug)` | **false positive** — `authenticate_shared_link/2` looks a link up *by* its bearer slug; that is the credential being presented, so there is no tenant to scope to |

One false positive in 13 findings. It is left in rather than special-cased: the
alternative is an exception for "lookups in functions named `authenticate_*`",
which would also hide a real one.

## Known limits

- The Elixir rules are `generic`/`regex` mode, so they match text rather than
  the AST. A `cast/3` call split across lines in an unusual way, or a field list
  built by a helper function, can slip past. The structural pack in
  `../plausible-security-elixir.yaml` does not have this limit but needs
  Opengrep or Semgrep Pro.
- `elixir-html-interpolation` does not know which interpolated values are
  attacker-controlled. It flags `#{usage.sites}` (an integer) the same as
  `#{team.name}`. It is scoped to `lib/**/*.ex`, where hand-built HTML is rare
  and mostly CRM code — 0 findings on today's `master`.
- `js-innerhtml-unescaped-label` keys off identifier names (`label`, `title`,
  `name`, …). A user-controlled value held in a differently named variable is
  missed. Widening it to every `${...}` in an `innerHTML` template makes it fire
  on `#6181`'s *fixed* version too, since that template still interpolates
  palette classes and pre-formatted numbers.
- `liveview-route-missing-live-session` cannot tell an intentionally public
  `live` route from an unprotected one. It is WARNING, not ERROR.
