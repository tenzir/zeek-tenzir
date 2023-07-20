##! This script defines utilities for post-processing Zeek logs with a Tenzir
##! pipeline.
##!
##! Usage:
##!
##!      event zeek_init()
##!        {
##!        # Import every log into a Tenzir node and delete it afterwards.
##!        Tenzir::postprocess("import");
##!        }
##!

@load base/frameworks/logging

module Tenzir;

export {
  ## Postprocesses logs with registered pipelines.
  ##
  ## info: A record holding meta-information about the log file to be
  ##       postprocessed.
  ##
  ## Returns: True unconditionally after executing all registered pipelines.
  global postprocessor: function(info: Log::RotationInfo): bool;

  ## Registers a pipeline for post-processing of a log file.
  ##
  ## pipeline: The pipeline operating on events, e.g., `import`.
  ##
  global postprocess: function(pipeline: string);

  ## Flag that controls whether to `rm -f` the original file after successfully
  ## executing a Tenzir pipeline. This flag only has an effect if there exists
  ## exactly one registered pipeline.
  const delete_after_postprocesing = T &redef;
}

## The set of pipelines to execute for every rotated log file.
global postprocessor_pipelines: set[string];

function Tenzir::postprocessor(info: Log::RotationInfo): bool
  {
  if ( info$writer != Log::WRITER_ASCII )
    return T;

  for ( pipeline in postprocessor_pipelines )
    {
    local filename = info$fname;
    local tql = fmt("from file %s read zeek-tsv | %s", filename, pipeline);
    local cmd = fmt("tenzir %s", safe_shell_quote(tql));
    if ( |postprocessor_pipelines| == 1 && delete_after_postprocesing )
      cmd = fmt("%s && rm -f %s", cmd, safe_shell_quote(filename));
    system(cmd);
    }

  return T;
  }

function Tenzir::postprocess(pipeline: string)
  {
  add postprocessor_pipelines[pipeline];
  }

# Hook ourselves into the postprocessing.
redef Log::default_rotation_postprocessors += {
  [Log::WRITER_ASCII] = Tenzir::postprocessor,
};
