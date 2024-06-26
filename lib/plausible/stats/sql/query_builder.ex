defmodule Plausible.Stats.SQL.QueryBuilder do
  @moduledoc false

  use Plausible

  import Ecto.Query
  import Plausible.Stats.Imported

  alias Plausible.Stats.{Base, Query, TableDecider, Util, Filters, Metrics}
  alias Plausible.Stats.SQL.Expression

  def build(query, site) do
    {event_metrics, sessions_metrics, _other_metrics} =
      query.metrics
      |> Util.maybe_add_visitors_metric()
      |> TableDecider.partition_metrics(query)

    join_query_results(
      build_events_query(site, query, event_metrics),
      event_metrics,
      build_sessions_query(site, query, sessions_metrics),
      sessions_metrics,
      query
    )
  end

  def shortname(metric) when is_atom(metric), do: metric
  def shortname(dimension), do: Plausible.Stats.Filters.without_prefix(dimension)

  defp build_events_query(_, _, []), do: nil

  defp build_events_query(site, query, event_metrics) do
    q =
      from(
        e in "events_v2",
        where: ^Filters.WhereBuilder.build(:events, site, query),
        select: ^Base.select_event_metrics(event_metrics)
      )

    on_ee do
      q = Plausible.Stats.Sampling.add_query_hint(q, query)
    end

    q
    |> join_sessions_if_needed(site, query)
    |> build_group_by(query)
    |> merge_imported(site, query, event_metrics)
    |> Base.maybe_add_conversion_rate(site, query, event_metrics)
  end

  defp join_sessions_if_needed(q, site, query) do
    if TableDecider.events_join_sessions?(query) do
      sessions_q =
        from(
          s in Base.query_sessions(site, query),
          select: %{session_id: s.session_id},
          where: s.sign == 1,
          group_by: s.session_id
        )

      from(
        e in q,
        join: sq in subquery(sessions_q),
        on: e.session_id == sq.session_id
      )
    else
      q
    end
  end

  def build_sessions_query(_, _, []), do: nil

  def build_sessions_query(site, query, session_metrics) do
    q =
      from(
        e in "sessions_v2",
        where: ^Filters.WhereBuilder.build(:sessions, site, query),
        select: ^Base.select_session_metrics(session_metrics, query)
      )

    on_ee do
      q = Plausible.Stats.Sampling.add_query_hint(q, query)
    end

    q
    |> join_events_if_needed(site, query)
    |> build_group_by(query)
    |> merge_imported(site, query, session_metrics)
  end

  def join_events_if_needed(q, site, query) do
    if Query.has_event_filters?(query) do
      events_q =
        from(e in "events_v2",
          where: ^Filters.WhereBuilder.build(:events, site, query),
          select: %{
            session_id: fragment("DISTINCT ?", e.session_id),
            _sample_factor: fragment("_sample_factor")
          }
        )

      on_ee do
        events_q = Plausible.Stats.Sampling.add_query_hint(events_q, query)
      end

      from(s in q,
        join: e in subquery(events_q),
        on: s.session_id == e.session_id
      )
    else
      q
    end
  end

  defp build_group_by(q, query) do
    Enum.reduce(query.dimensions, q, fn dimension, q ->
      q
      |> select_merge(^%{shortname(dimension) => Expression.dimension(dimension, query)})
      |> group_by(^Expression.dimension(dimension, query))
    end)
  end

  defp build_order_by(q, query, mode) do
    Enum.reduce(query.order_by, q, &build_order_by(&2, query, &1, mode))
  end

  def build_order_by(q, query, {metric_or_dimension, order_direction}, :inner) do
    order_by(
      q,
      [t],
      ^{
        order_direction,
        if(
          Metrics.metric?(metric_or_dimension),
          do: dynamic([], selected_as(^shortname(metric_or_dimension))),
          else: Expression.dimension(metric_or_dimension, query)
        )
      }
    )
  end

  def build_order_by(q, _query, {metric_or_dimension, order_direction}, :outer) do
    order_by(
      q,
      [t],
      ^{
        order_direction,
        dynamic([], selected_as(^shortname(metric_or_dimension)))
      }
    )
  end

  defmacrop select_join_fields(q, list, table_name) do
    quote do
      Enum.reduce(unquote(list), unquote(q), fn metric_or_dimension, q ->
        select_merge(
          q,
          ^%{
            shortname(metric_or_dimension) =>
              dynamic(
                [e, s],
                selected_as(
                  field(unquote(table_name), ^shortname(metric_or_dimension)),
                  ^shortname(metric_or_dimension)
                )
              )
          }
        )
      end)
    end
  end

  defp join_query_results(nil, _, nil, _, _query), do: nil

  defp join_query_results(events_q, _, nil, _, query),
    do: events_q |> build_order_by(query, :inner)

  defp join_query_results(nil, _, sessions_q, _, query),
    do: sessions_q |> build_order_by(query, :inner)

  defp join_query_results(events_q, event_metrics, sessions_q, sessions_metrics, query) do
    join(subquery(events_q), :left, [e], s in subquery(sessions_q),
      on: ^build_group_by_join(query)
    )
    |> select_join_fields(query.dimensions, e)
    |> select_join_fields(event_metrics, e)
    |> select_join_fields(List.delete(sessions_metrics, :sample_percent), s)
    |> build_order_by(query, :outer)
  end

  defp build_group_by_join(%Query{dimensions: []}), do: true

  defp build_group_by_join(query) do
    query.dimensions
    |> Enum.map(fn dim ->
      dynamic([e, s], field(e, ^shortname(dim)) == field(s, ^shortname(dim)))
    end)
    |> Enum.reduce(fn condition, acc -> dynamic([], ^acc and ^condition) end)
  end
end
