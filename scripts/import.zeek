@load tenzir

# Activate log rotation by redef the rotation interval to a non-zero value.
redef Log::default_rotation_interval = 10 mins;

event zeek_init()
  {
  Tenzir::postprocess("import");
  }
