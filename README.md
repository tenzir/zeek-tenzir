# Bro & VAST

This package enables Bro to communicate with
[VAST](https://github.com/vast-io/vast), a scalable plaform for network
forensics.

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

If you're no a Bro hacker and just want to enjoy the new capabilities, load the
following script:

```bro
@load bro-vast/intel.bro
```

See the `export` section for some tuning knobs. The script monitors a file
`VAST::intel_filename` (which defaults to `vast.intel`) with intelligence data
in the form required by the [intelligence framework][bro-intel-framework].
If you want to make available new entries to this file to the intelligence
framework, set `VAST::insert_intel` to `T`. It defaults to `F` because we
assume that the intel for VAST has already been made available to the framework
separately.

See the file [vast.intel](vast.intel) for an example intelligence file.

## License

This package comes with a [BSD license](LICENSE).

[intel-framework]: https://www.bro.org/sphinx-git/frameworks/intel.html
