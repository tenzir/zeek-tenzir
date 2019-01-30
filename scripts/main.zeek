##! The main component of the VAST package with general declarations and
##! definitions.

@load ./utils

@load base/frameworks/broker

module VAST;

export {
  ## The hostname or address where ``zeek-to-vast`` runs.
  const bridge_host = "127.0.0.1" &redef;

  ## The port where ``zeek-to-vast`` listens.
  const bridge_port = 43000/tcp &redef;

  ## Flag that indicates whether we're connected to the VAST bridge.
  global connected_to_bridge = F;

  ## Raised when the Broker connection to the bridge has been established.
  global bridge_up: event();

  ## Raised when the Broker connection to the bridge has been lost.
  global bridge_down: event();
}

# The Broker topic for the control channel.
const control_topic = "/vast/control";

# The Broker topic for the data channel.
const data_topic = "/vast/data";

# The event that this script sends to VAST to create a new query.
global query: event(uuid: string, expression: string);

# The event that VAST sends back in response to a query.
global result: event(uuid: string, data: any);

## Performs a lookup of an expression in VAST. Results arrive asynchronously
## via the ``result`` event.
##
## expresion: The query expression.
##
## Returns: The UUID of the query.
function lookup(expression: string): string
  {
  local query_id = random_uuid();
  local e = Broker::make_event(query, query_id, expression);
  Broker::publish(control_topic, e);
  return query_id;
  }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
  {
  if ( ! endpoint?$network )
    return;
  local net = endpoint$network;
  # FIXME: this conditional breaks if bridge_host is a hostname because
  # net$address is always a (resolved) address.
  if ( net$address == bridge_host && net$bound_port == bridge_port )
    event VAST::bridge_up();
  }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
  {
  if ( ! endpoint?$network )
    return;
  local net = endpoint$network;
  # FIXME: see note above.
  if ( net$address == bridge_host && net$bound_port == bridge_port )
    event VAST::bridge_down();
  }

event bridge_up()
  {
  connected_to_bridge = T;
  }

event bridge_down()
  {
  connected_to_bridge = F;
  }

event zeek_init()
  {
  Broker::subscribe(data_topic);
  Broker::peer(bridge_host, bridge_port);
  }
