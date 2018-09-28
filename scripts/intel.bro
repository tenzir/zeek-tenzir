##! The intelligence component of the VAST package enables historic lookups for
##! intel items.

@load ./main

@load base/frameworks/broker
@load base/frameworks/intel

module VAST;

export {
  ## The filename containing intelligence data that results
  const intel_filename = "vast.intel" &redef;

  ## Flag that indicates whether we should insert intel items into the
  ## framework for further matching.
  const intel_insert = T &redef;
}

# Maps queries created from the Intell::match event
global intel_queries: table[string] of string;

# Sent from VAST.
event result(uuid: string, data: any)
  {
  # A valid result is a vector over data. A null value signifies that the query
  # has terminated.
  switch (data)
    {
    default:
      print "query", uuid, "terminated";
      delete intel_queries[uuid];
      break;
    case type vector of any as xs:
      print xs; # TODO: do something more exciting than just printing.
      break;
    }
  }

event new_item(desc: Input::EventDescription, ev: Input::Event, item: Intel::Item)
  {
  if ( item$indicator_type == Intel::ADDR )
    {
    local address = to_addr(item$indicator);
    local expression = fmt(":addr == %s", address);
    local uuid = lookup(expression);
    print "new intel item with address: ", address;
    intel_queries[uuid] = expression;
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
