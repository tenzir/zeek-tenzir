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

## Configuration

See the `export` section of the scripts for a complete description of tuning
knobs.

### intel.bro

This script defines the intelligence framework integration. The script monitors
a file `VAST::intel_filename` (which defaults to `vast.intel`) with
intelligence data in the form required by the [intelligence
framework][bro-intel-framework]. If you want to make available new entries to
this file to the intelligence framework, set `VAST::insert_intel` to `T`. It
defaults to `F` because we assume that the intel for VAST has already been made
available to the framework separately.

See the file [vast.intel](vast.intel) for an example intelligence file.

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
