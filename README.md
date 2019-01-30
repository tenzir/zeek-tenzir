# Zeek & VAST

This package enables [Zeek](https://zeek.org) to communicate with [VAST][vast],
a scalable plaform for network forensics. Combining VAST and Zeek allows threat
hunters to automate routine tasks, such as correlating new intelligence feed
items with data from the past.

## Features

- Historic intelligence lookups: when new intelligence becomes available,
  go back in time and look for connections that involved the new intelligence.

- Query arbitrary data in VAST.

## Installation

The scripts ship as a [Zeek package][zeek-pkg-mgr]. Installation follows the
standard procedure:

```shell
zkg install zeek-vast
```

## Usage

First, make sure that VAST and [`zeek-to-vast`][zeek-to-vast] are running,
otherwise the scripts will not be able to communicate with VAST.

To enable historic intelligence lookups, just load the following script:

```bro
@load zeek-vast/intel.zeek
```

Zeek then generates a new file `historic-intel.log` with the results of historic
intelligence lookups.

To test your setup locally, you can load the [example intel file](example.intel)
as follows:

```shell
zeek 'Intel::read_files += {"example.intel"}' scripts/intel.zeek
```

## Configuration

See the `export` section of the scripts for a complete description of tuning
knobs.

### intel.zeek

This script integrates VAST with the [intelligence framework][intel-framework]:
Whenever Zeek processes a new intelligence item, the script performs a historic
lookup for the new item in VAST. If there exists relevant data, VAST sends the
result back, which the scripts then writes into the file `historic-intel.log`.

If there's currently no connection to VAST, then the script queues the item
until the connection becomes available again.

### main.zeek

This script defines the basic functions to communicate with VAST. You can
configure how Zeek should connect to `zeek-to-vast` with the two variables
`VAST::bridge_host` and `VAST::bridge_port`. They default to `127.0.0.1` and
`43000/tcp`.

## License

This Zeek package comes with a [BSD license](LICENSE).

[vast]: https://github.com/vast-io/vast
[intel-framework]: https://docs.zeek.org/en/stable/frameworks/intel.html
[zeek-to-vast]: https://github.com/vast-io/vast/tree/master/tools/zeek-to-vast
[zeek-pkg-mgr]: https://docs.zeek.org/projects-package-manager
