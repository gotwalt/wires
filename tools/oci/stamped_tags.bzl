"Generate stamped repo_tags for oci_load with git commit SHA"

load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS", "maybe_stamp")

def _stamped_tags_impl(ctx):
    out = ctx.actions.declare_file(ctx.attr.name + ".tags.txt")
    stamp = maybe_stamp(ctx)

    if stamp:
        ctx.actions.run_shell(
            inputs = [stamp.stable_status_file],
            outputs = [out],
            command = """\
COMMIT=$(grep '^STABLE_GIT_COMMIT ' "$1" | cut -d' ' -f2)
SHORT=$(echo "$COMMIT" | cut -c1-12)
echo "{name}:$SHORT" > "$2"
echo "{name}:latest" >> "$2"
""".format(name = ctx.attr.image_name),
            arguments = [stamp.stable_status_file.path, out.path],
            mnemonic = "StampedTags",
        )
    else:
        ctx.actions.write(out, ctx.attr.image_name + ":latest\n")

    return DefaultInfo(files = depset([out]))

stamped_tags = rule(
    implementation = _stamped_tags_impl,
    attrs = dict({
        "image_name": attr.string(
            mandatory = True,
            doc = "The repository name for the image (e.g. 'registry', 'node/server').",
        ),
    }, **STAMP_ATTRS),
)
