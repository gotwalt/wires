"Rules for managing platform transitions."

def _exec_files_impl(ctx):
    """Collects files from srcs built in the exec configuration."""
    all_files = []
    for src in ctx.attr.srcs:
        all_files.append(src[DefaultInfo].files)
    return [DefaultInfo(files = depset(transitive = all_files))]

exec_files = rule(
    implementation = _exec_files_impl,
    doc = "Wraps srcs with cfg='exec' so they are built for the execution " +
          "platform, making them immune to target platform transitions. " +
          "Use this for platform-independent build outputs (e.g. WASM, JS) " +
          "that are consumed by OCI image targets with platform transitions.",
    attrs = {
        "srcs": attr.label_list(
            cfg = "exec",
            allow_files = True,
        ),
    },
)
