##! The intelligence component of the VAST package enables historic lookups for
##! intel items.

@load ./main

@load base/init-bare
@load base/frameworks/broker
@load base/frameworks/cluster
@load base/frameworks/intel
@load base/frameworks/logging
@load base/frameworks/reporter

module VAST;

export {
  # Append the value LOG to the Log::ID enumerable.
  redef enum Log::ID += { LOG };

  ## The record type which contains the column fields of the log.
  type Info: record {
    ## The timestamp of the historic connection.
    ts: time &log;

    ## The UID of the historic connection.
    uid: string &log;

    ## The connection 5-tuple of the historic connection.
    id: conn_id &log;

    ## The indicator that matched the historic connection.
    indicator: string &log;

    ## The type of :bro:id:`indicator`.
    indicator_type: Intel::Type &log;

    ## The difference in time since Bro got the indicator and the historic
    ## connection.
    age: interval &log;
  };
}

## The context for a historic VAST lookup.
type QueryContext: record{
  ## The query expression.
  expression: string;

  ## The time when Bro issued the query.
  start: time;

  ## The intel item for this query.
  item: Intel::Item;
};

# Unprocessed intel items
global unprocessed_intel_items: set[Intel::Item];

# Maps VAST query IDs to additional context.
global intel_queries: table[string] of QueryContext;

# Exporting this function prior to its definition works around a problem with
# the Intel framework API: we need to be able to call this function down below
# when we're opening the Intel module namespace temporarily.
export {
  global queue_or_lookup_intel: function(item: Intel::Item);
}

# Creates a query expression for a given intel item. If the item cannot be
# translated into a VAST expression, the function returns the empty string.
function make_expression(item: Intel::Item): string
  {
  if ( item$indicator_type == Intel::ADDR )
    {
    local address = to_addr(item$indicator);
    return fmt("&type == \"bro::conn\" && :addr == %s", address);
    }
  else if ( item$indicator_type == Intel::SUBNET )
    {
    local prefix = to_subnet(item$indicator);
    return fmt("new intel item with subnet: %s", prefix);
    }
  return "";
  }

# Issues a historical query for an intel item.
function historic_intel_lookup(item: Intel::Item)
  {
  local expr = make_expression(item);
  if ( |expr| == 0 )
    return;  # Unsupported intel type.
  local uuid = lookup(expr);
  intel_queries[uuid] = [$expression=expr, $start=current_time(), $item=item];
  }

# Helper function that either dispatches the lookup directly or queues the item
# until VAST is available.
function queue_or_lookup_intel(item: Intel::Item)
  {
  if ( connected_to_bridge )
    historic_intel_lookup(item);
  else
    add unprocessed_intel_items[item];
  }

# Because the intel framework does not have a public API for hooking the
# addition of new intel items, we have to futz with some framework internals to
# be able to interpose at the right place.
module Intel;

@if ( ! Cluster::is_enabled()
      || Cluster::local_node_type() == Cluster::MANAGER )

event new_item(item: Item)
  {
  VAST::queue_or_lookup_intel(item);
  }

@endif

module VAST;

# Takes a historic conn log and correlates it with the new intel host.
function handle_conn_log_entry(ctx: QueryContext, entry: vector of any)
  {
  # Sanity checks that we're dealing with a conn log.
  local xs = entry as vector of any;
  if ( |xs| < 20 )
    Reporter::fatal("not operating on a conn.log");
  local ts = xs[0] as time;
  local uid = xs[1] as string;
  local orig_h = xs[2] as addr;
  local orig_p = xs[3] as port;
  local resp_h = xs[4] as addr;
  local resp_p = xs[5] as port;
  local id: conn_id = [$orig_h=orig_h,
                       $orig_p=orig_p,
                       $resp_h=resp_h,
                       $resp_p=resp_p];
  Log::write(LOG, [$ts=ts,
                   $uid=uid,
                   $id=id,
                   $indicator=ctx$item$indicator,
                   $indicator_type=ctx$item$indicator_type,
                   $age=(ctx$start - ts)]);
  }

# Query response sent from VAST.
event result(uuid: string, data: any)
  {
  switch ( data )
    {
    default:
      # Once the query has terminated, VAST sends null value.
      local runtime = current_time() - intel_queries[uuid]$start;
      Reporter::info(fmt("VAST query %s terminated in %f secs", uuid, runtime));
      delete intel_queries[uuid];
      break;
    case type vector of any as xs:
      # VAST sends a vector [x, xs] where 'x' is the event name and 'xs' the
      # data in the form of a vector.
      if ( |xs| != 2 )
        Reporter::fatal("invalid VAST result event");
      if ( (xs[0] as string) == "bro::conn" )
        handle_conn_log_entry(intel_queries[uuid], xs[1]);
      else
        Reporter::warning(fmt("can only process conn logs, not %s", xs[0]));
      break;
    }
  }

# Process all queries that have accummulated.
event bridge_up()
  {
  for ( item in unprocessed_intel_items )
    historic_intel_lookup(item);
  }

event bro_init()
  {
  Log::create_stream(LOG, [$columns=Info, $path="historic-intel"]);
  }
