# Bro & VAST

This package enables Bro to communicate with [VAST][vast], a scalable plaform
for network forensics.

## Features

- Historic intelligence lookups: when new intelligence becomes available,
  go back in time and look for connections that involved the new intelligence.

- Query arbitrary data in VAST.

## Installation

The scripts ship as a Bro package. Installation follows the standard procedure:

```shell
bro-pkg install bro-vast
```

## Usage

First, make sure that `vast` and [`bro-to-vast`][bro-to-vast] are running,
otherwise the scripts will not be able to communicate with VAST.

To enable historic intelligence lookups, just load the following script:

```bro
@load bro-vast/intel.bro
```

To test your setup locally, you can load the [example intel file](vast.intel)
as follows:

```shell
bro 'Intel::read_files += {"vast.intel"}' scripts/intel.bro
```

The intel framework

## Configuration

See the `export` section of the scripts for a complete description of tuning
knobs.

### intel.bro

This script defines the [intelligence framework][bro-intel-framework]
integration. Whenever new intelligence is added, the script performs a historic
intel lookup for the item. If there's currently no connection to VAST, then the
script queues the item until the connection becomes available again.

### main.bro

This script defines the basic functions to communicate with VAST. You can
configure how Bro should connect to `bro-to-vast` with the two variables
`VAST::bridge_host` and `VAST::bridge_port`. They default to `127.0.0.1` and
`43000/tcp`.

## License

This Bro package comes with a [BSD license](LICENSE).

[vast]: https://github.com/vast-io/vast
[bro-to-vast]: https://github.com/vast-io/vast/tree/master/tools/bro-to-vast
[intel-framework]: https://www.bro.org/sphinx-git/frameworks/intel.html
