# Zeek & Tenzir

This [Zeek](https://zeek.org) package provides the integration with
[Tenzir](https://docs.tenzir.com).

## Get Started

Install the package and you're good to go:

```bash
zkg install zeek-tenzir
```

## Use Cases

Here are a few things you can do with the Tenzir package.

### Post-process Logs with Pipelines

```zeek
event zeek_init()
  {
  Tenzir::postprocess("import"); 
  }
```

## License

This Zeek package comes with a [BSD 3-clause license](LICENSE).
