defmodule Plausible.ReportedLiveViewAuthzTest do
  @moduledoc """
  Verification of two externally reported findings:

    * lib/plausible_web/live/team_management.ex:275 — "update-team" performs a
      team rename with no role check.
    * lib/plausible_web/live/subscription_settings.ex:61 — billing data is
      rendered without a role check, the reporter claiming the mount guard
      "does not run for completed teams".

  Each report is turned into an executable attack. The test names record what
  was actually observed, which is not in every case what was reported.
  """

  use PlausibleWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Plausible.Repo

  defp team_general_path, do: Routes.settings_path(PlausibleWeb.Endpoint, :team_general)
  defp subscription_path, do: "/settings/billing/subscription"

  defp secret_key_base do
    :plausible
    |> Application.fetch_env!(PlausibleWeb.Endpoint)
    |> Keyword.fetch!(:secret_key_base)
  end

  defp logged_in_conn(user) do
    Phoenix.ConnTest.build_conn()
    |> Plausible.TestUtils.prepare_conn()
    |> init_session()
    |> PlausibleWeb.UserAuth.log_in_user(user)
    |> Phoenix.ConnTest.recycle()
    |> Map.put(:secret_key_base, secret_key_base())
    |> init_session()
  end

  defp log_in_as(conn, user, team) do
    conn
    |> Plausible.TestUtils.prepare_conn()
    |> init_session()
    |> PlausibleWeb.UserAuth.log_in_user(user)
    |> Phoenix.ConnTest.recycle()
    |> Map.put(:secret_key_base, secret_key_base())
    |> init_session()
    |> Plug.Conn.fetch_session()
    |> Plug.Conn.put_session(:current_team_id, team.identifier)
  end

  ##############################################################################
  # REPORT A — team_management.ex:275 "update-team"
  ##############################################################################
  describe "REPORT A team_management.ex:275 update-team has no role check" do
    setup [:create_user, :log_in, :create_team, :setup_team]

    test "CONFIRMED: a viewer renames the team through the LiveView event", %{team: team} do
      viewer = add_member(team, role: :viewer)
      original_name = team.name

      conn = log_in_as(Phoenix.ConnTest.build_conn(), viewer, team)

      # The viewer can load the settings page that live_renders TeamManagement.
      assert conn |> get(team_general_path()) |> html_response(200)

      conn = log_in_as(Phoenix.ConnTest.build_conn(), viewer, team)
      conn = assign(conn, :live_module, PlausibleWeb.Live.TeamManagement)
      {:ok, lv, _html} = live(conn, team_general_path())

      # A forged event: no DOM control is required to push it.
      render_hook(lv, "update-team", %{"team" => %{"name" => "Owned By Viewer"}})

      renamed = Repo.reload!(team)

      assert renamed.name == "Owned By Viewer",
             "expected a viewer to be able to rename the team via the LiveView event"

      refute renamed.name == original_name
    end

    test "CONTRAST: the equivalent HTTP endpoint rejects the same viewer", %{team: team} do
      viewer = add_member(team, role: :viewer)
      original_name = Repo.reload!(team).name

      conn = log_in_as(Phoenix.ConnTest.build_conn(), viewer, team)

      result = post(conn, "/settings/team/general/name", %{"team" => %{"name" => "Owned By HTTP"}})

      # AuthorizeTeamAccess, [:owner, :admin] guards this action.
      assert result.status in [302, 404]
      assert Repo.reload!(team).name == original_name
    end

    test "CONTRAST: an editor is also below the role bar the HTTP endpoint enforces", %{
      team: team
    } do
      editor = add_member(team, role: :editor)
      original_name = Repo.reload!(team).name

      conn = log_in_as(Phoenix.ConnTest.build_conn(), editor, team)

      result =
        post(conn, "/settings/team/general/name", %{"team" => %{"name" => "Owned By Editor"}})

      assert result.status in [302, 404]
      assert Repo.reload!(team).name == original_name

      # ... yet the same editor renames the team over the socket.
      conn = log_in_as(Phoenix.ConnTest.build_conn(), editor, team)
      conn = assign(conn, :live_module, PlausibleWeb.Live.TeamManagement)
      {:ok, lv, _html} = live(conn, team_general_path())

      render_hook(lv, "update-team", %{"team" => %{"name" => "Owned By Editor LV"}})

      assert Repo.reload!(team).name == "Owned By Editor LV"
    end
  end

  ##############################################################################
  # REPORT B — subscription_settings.ex:61
  ##############################################################################
  describe "REPORT B subscription_settings.ex:61 billing data without a role check" do
    setup [:create_user, :log_in, :create_team, :setup_team]

    test "REPORT IS INVERTED: on a completed team the mount guard does run and redirects a viewer",
         %{team: team} do
      viewer = add_member(team, role: :viewer)
      conn = log_in_as(Phoenix.ConnTest.build_conn(), viewer, team)

      assert Plausible.Teams.setup?(Repo.reload!(team))

      assert {:error, {:redirect, %{to: to}}} = live(conn, subscription_path())
      assert to == "/sites"
    end

    test "the guard also redirects an editor, and admits owner and billing roles", %{
      team: team,
      user: owner,
      conn: owner_conn
    } do
      editor = add_member(team, role: :editor)
      billing_member = add_member(team, role: :billing)

      assert {:error, {:redirect, _}} =
               live(log_in_as(Phoenix.ConnTest.build_conn(), editor, team), subscription_path())

      assert {:ok, _lv, _html} =
               live(log_in_as(Phoenix.ConnTest.build_conn(), billing_member, team), subscription_path())

      assert owner.id
      assert {:ok, _lv, _html} = live(owner_conn, subscription_path())
    end
  end

  describe "REPORT B follow-up: the branch the guard genuinely skips" do
    test "NOT EXPLOITABLE: a guest cannot make another team current, so no billing data is loaded" do
      owner = new_user()
      site = new_site(owner: owner)
      team = Repo.preload(site, :team).team

      # Layout.persist completes setup before persisting any member, so :guest is
      # the only non-owner role that can exist on a team that is not set up --
      # and a non-setup team is exactly where the mount guard is skipped.
      refute Plausible.Teams.setup?(team)

      insert(:subscription, team: team, next_bill_amount: "123.45", currency_code: "USD")

      guest = new_user()
      add_guest(site, role: :viewer, user: guest)
      assert {:ok, :guest} = Plausible.Teams.Memberships.team_role(team, guest)

      conn = logged_in_conn(guest)

      # Follow a ?__team= link of the kind Plausible mails out. AuthPlug honours
      # the parameter after a membership check only -- no role, no setup check.
      assert {:ok, lv, html} = live(conn, subscription_path() <> "?__team=#{team.identifier}")

      assigns = :sys.get_state(lv.pid).socket.assigns

      # The guard is indeed skipped, but current_team never resolves: guest
      # memberships are excluded from the session user's preload
      # (lib/plausible/auth/user_sessions.ex:117, `on: tm.role != :guest`).
      assert is_nil(assigns.current_team)
      assert is_nil(assigns.current_team_role)

      # So nothing belonging to the owner is loaded or rendered.
      assert is_nil(assigns.subscription)
      refute html =~ "123.45"
      refute html =~ "Renews on"
    end

    test "the exclusion that makes it safe: a guest membership is not in the session user's teams" do
      owner = new_user()
      site = new_site(owner: owner)
      team = Repo.preload(site, :team).team

      guest = new_user()
      add_guest(site, role: :viewer, user: guest)

      # Present in the database ...
      assert {:ok, :guest} = Plausible.Teams.Memberships.team_role(team, guest)

      # ... absent from what AuthPlug matches ?__team= against.
      conn = get(logged_in_conn(guest), "/sites?__team=#{team.identifier}")

      assert conn.assigns.current_user.team_memberships == []
      assert is_nil(conn.assigns[:current_team])
      assert is_nil(conn.assigns[:current_team_role])
    end
  end
end
