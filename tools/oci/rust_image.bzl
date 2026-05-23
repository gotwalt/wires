"rust_image macro for OCI containers"

load("@bazel_lib//lib:transitions.bzl", "platform_transition_filegroup")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_load")
load("@tar.bzl", "tar")
load("//tools/oci:stamped_tags.bzl", "stamped_tags")

def rust_image(name, binary, base = "@distroless_base"):
    """Create a distroless OCI image from a Rust binary.

    Args:
        name: The name of the image target.
        binary: The rust_binary target to package.
        base: The base image (default: distroless/base which includes glibc).
    """
    tar(
        name = name + "_app_layer",
        srcs = [binary],
        mtree = [
            "./opt/app type=file content=$(execpath {})".format(binary),
        ],
    )
    oci_image(
        name = name + "_image",
        base = base,
        tars = [
            name + "_app_layer",
        ],
        entrypoint = [
            "/opt/app",
        ],
    )
    platform_transition_filegroup(
        name = name,
        srcs = [name + "_image"],
        target_platform = select({
            "@platforms//cpu:arm64": "//tools/platforms:linux_aarch64",
            "@platforms//cpu:x86_64": "//tools/platforms:linux_x86_64",
        }),
    )
    stamped_tags(
        name = name + "_tags",
        image_name = native.package_name(),
        stamp = 1,
    )
    oci_load(
        name = name + ".load",
        image = name,
        repo_tags = name + "_tags",
    )
