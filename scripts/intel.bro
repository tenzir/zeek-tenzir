##! The intelligence component of the VAST package enables historic lookups for
##! intel items.

@load ./main

@load base/frameworks/broker
@load base/frameworks/intel
@load base/frameworks/notice
@load base/frameworks/reporter

module VAST;

export {
  redef enum Notice::Type += {
    ## When a new intel item is added to the the file
    ## :bro:id:`VAST::intel_filename`, VAST performs a historic query to look
    ## for connections prior to the release of the new item. If found, Bro
    ## generates this notice.
    Historic_Intel,
  };

  ## The filename containing intelligence data that results
  const intel_filename = "vast.intel" &redef;

  ## Flag that indicates whether we should insert intel items into the
  ## framework for further matching.
  const intel_insert = F &redef;
}

## The context for a historic VAST lookup.
type QueryContext: record{
  ## The query expression.
  expression: string;

  ## The time when Bro issued the query.
  start: time;

  ## If intel was of type ADDR, then this field contains the host.
  host: addr &optional;

  ## If intel was of type SUBNET, then this field contains the host.
  prefix: subnet &optional;
};

# Maps hosts occurring in historic intel to a list of timestamps when the intel
# has occurred in the past.
type HostMap: table[addr] of set[time];

# Maps VAST query IDs to additional context.
global intel_queries: table[string] of QueryContext;

# Hosts who triggered intel prior to the publication of the intel item.
global historic_intel: table[addr] of HostMap;

# Takes a historic conn log and correlates it with the new intel host.
function handle_conn_log_entry(intel_host: addr, entry: vector of any)
  {
  # Sanity checks that we're dealing with a conn log.
  local xs = entry as vector of any;
  if ( |xs| < 20 )
    Reporter::fatal("not operating on a conn.log");
  local orig_h = xs[2] as addr;
  local resp_h = xs[4] as addr;
  # Figure out the other side of the communication.
  local other = 0.0.0.0;
  if ( orig_h == intel_host )
    other = resp_h;
  else if ( resp_h == intel_host )
    other = orig_h;
  if ( other == 0.0.0.0 )
    return;
  # Record the timestamp of the historic connection.
  local ts = xs[0] as time;
  if ( intel_host !in historic_intel )
    historic_intel[intel_host] = HostMap();
  local hosts = historic_intel[intel_host];
  if ( other !in hosts )
    hosts[other] = set();
  add hosts[other][ts];
  # Generate a notice for every historic connection.
  local since = current_time() - ts;
  local message = fmt("historic intel seen from %s to %s %f secs ago",
                      orig_h, resp_h, since);
  NOTICE([$note=Historic_Intel,
          $n=|hosts[other]|,
          $msg=message,
          $sub=cat(intel_host),
          $src=orig_h,
          $dst=resp_h,
          $identifier=cat(intel_host, other)]);
  }

# Query response sent from VAST.
event result(uuid: string, data: any)
  {
  # A valid result is a vector over data. A null value signifies that the query
  # has terminated.
  switch (data)
    {
    default:
      local runtime = current_time() - intel_queries[uuid]$start ;
      Reporter::info(fmt("query %s terminated in %f secs", uuid, runtime));
      delete intel_queries[uuid];
      break;
    case type vector of any as xs:
      # VAST sends a vector [x, xs] where 'x' is the event name and 'xs' the
      # data in the form of a vector.
      if ( |xs| != 2 )
        Reporter::fatal("invalid VAST result");
      local intel_host = intel_queries[uuid]$host;
      if ( (xs[0] as string) == "bro::conn" )
        handle_conn_log_entry(intel_host, xs[1]);
      else
        Reporter::warning(fmt("can only process conn logs, not %s", xs[0]));
      break;
    }
  }

event new_item(desc: Input::EventDescription, ev: Input::Event,
               item: Intel::Item)
  {
  local expression: string;
  local uuid: string;
  if ( item$indicator_type == Intel::ADDR )
    {
    local address = to_addr(item$indicator);
    Reporter::info(fmt("new intel item with address: %s", address));
    expression = fmt(":addr == %s", address);
    uuid = lookup(expression);
    intel_queries[uuid] = [$expression=expression,
                           $start=current_time(),
                           $host=address];
    }
  else if ( item$indicator_type == Intel::SUBNET )
    {
    local prefix = to_subnet(item$indicator);
    Reporter::info(fmt("new intel item with subnet: %s", prefix));
    expression = fmt(":addr in %s", prefix);
    uuid = lookup(expression);
    intel_queries[uuid] = [$expression=expression,
                           $start=current_time(),
                           $prefix=prefix];
    }
  else
    {
    Reporter::warning(fmt("unsupported indicator type: %s",
                          item$indicator_type));
    }
  if ( intel_insert )
    Intel::insert(item);
  }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
  {
  # We do not add the intelligence file in bro_init() because the peering is
  # not yet established at this point. Consequently, all existing intel items
  # would not result in a VAST lookup.
  Input::add_event([$source=intel_filename,
      $reader=Input::READER_ASCII,
      $mode=Input::STREAM,
      $name=cat("intel-", intel_filename),
      $fields=Intel::Item,
      $ev=new_item]);
  }
