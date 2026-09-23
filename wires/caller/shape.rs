//! Output shaping for `wires call`: `--jq`, `--head`, `--max-bytes`.
//!
//! The CLI advantage an agent gets from `gh … --jq …` is that it filters a
//! command's output *before* it reaches the model's context (board card 16).
//! An agent in a wires-only sandbox has no shell, so no `| jq`, `| head`: these
//! flags give it the same filtering **in-process**. Nothing is spawned locally
//! and nothing is sent to the host: the remote stdout arrives, is shaped here,
//! and only the shaped bytes are written out. The remote stderr and exit code
//! pass through untouched.
//!
//! The stages run in a fixed order: `--jq` (a jq program over every JSON
//! value in stdout; strings print raw and everything else as compact JSON,
//! the same as `gh --jq`), then `--head N` (the first N lines), then
//! `--max-bytes N` (never splitting a UTF-8 character, with a note on stderr
//! saying how much was dropped).
//!
//! The jq engine is [jaq](https://github.com/01mf02/jaq), a pure-Rust jq.
//! A filter is compiled once up front ([`Shape::new`]), so a typo fails with
//! exit [`EXIT_SHAPE`] *before* anything is dialed.

use std::fmt;

use clap::Args;
use jaq_core::load::{Arena, File, Loader};
use jaq_core::{Compiler, Ctx, Vars, data, unwrap_valr};
use jaq_json::Val;

/// Exit code when shaping fails: a jq filter that doesn't compile, or one
/// that errors on the remote output (like `jq`'s own usage/compile errors).
/// Never replaces a non-zero remote exit code; see [`exit_code`].
pub const EXIT_SHAPE: i32 = 2;

/// How to call and filter without a shell, for `wires tools list` (and the
/// agent reading it). `wires mcp` says the same in its own terms.
pub const CALL_HINT: &str = "call: wires call <name> [--jq FILTER] [--head N] [--max-bytes N] -- <args>. \
Filter with the command's own flags (e.g. gh --json f --jq …) or --jq/--head/--max-bytes; \
there is no shell, so pipes are not available.";

/// How much of an unparseable remote stdout an error message quotes.
const SNIPPET_BYTES: usize = 160;

/// `wires call`'s shaping flags, all optional and all local.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct ShapeArgs {
    /// Filter the remote stdout with this jq program, in-process (no local
    /// `jq` or shell). Strings print raw, other values as compact JSON, one
    /// per line — as with `gh --jq`. A filter that doesn't compile exits 2
    /// before the call is made.
    #[arg(long, value_name = "FILTER")]
    pub jq: Option<String>,
    /// Keep only the first N lines of the (filtered) stdout.
    #[arg(long, value_name = "N")]
    pub head: Option<usize>,
    /// Keep at most N bytes of the (filtered) stdout, cut on a character
    /// boundary; a note on stderr says how much was dropped.
    #[arg(long, value_name = "N")]
    pub max_bytes: Option<usize>,
}

/// A shaping failure: the jq filter didn't compile, the remote stdout wasn't
/// JSON, or the filter raised an error. Maps to exit [`EXIT_SHAPE`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShapeError(String);

impl ShapeError {
    /// The human-readable reason.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ShapeError {}

/// A jq program that is known to compile.
///
/// Holds the source, not the compiled filter: jaq's values are `Rc`-based
/// and not `Send`, so the filter is rebuilt (cheaply) where it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JqProgram(String);

impl JqProgram {
    /// Compile `src` once to check it; the error names what jaq expected.
    ///
    /// `JqProgram::new(".[] | .name")` is `Ok`; `JqProgram::new(".[")` is an
    /// error ("expected …"). (A binary crate has no doctests; the unit tests
    /// below cover both.)
    pub fn new(src: &str) -> Result<Self, ShapeError> {
        with_filter(src, |_| ())?;
        Ok(Self(src.to_owned()))
    }

    /// Run the program over every JSON value in `input` (one document, or
    /// several separated by whitespace, as `jq` reads them). Returns the
    /// rendered outputs so far and, if it stopped early, why.
    pub fn run(&self, input: &[u8]) -> (Vec<u8>, Option<ShapeError>) {
        let mut out = Vec::new();
        let err = with_filter(&self.0, |filter| {
            for value in jaq_json::read::parse_many(input) {
                let value = match value {
                    Ok(v) => v,
                    Err(e) => return Some(not_json(input, &e.to_string())),
                };
                let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));
                for r in filter.id.run((ctx, value)).map(unwrap_valr) {
                    match r {
                        Ok(v) => render(&v, &mut out),
                        Err(e) => return Some(ShapeError(format!("--jq: {e}"))),
                    }
                }
            }
            None
        });
        match err {
            Ok(e) => (out, e),
            Err(e) => (out, Some(e)),
        }
    }
}

/// The compiled shaping stages for one call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shape {
    jq: Option<JqProgram>,
    head: Option<usize>,
    max_bytes: Option<usize>,
}

/// What shaping made of the remote stdout.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shaped {
    /// The bytes to write to stdout.
    pub stdout: Vec<u8>,
    /// Notes for stderr (e.g. `--max-bytes` truncation), one per line.
    pub notes: Vec<String>,
    /// Set when `--jq` failed; `stdout` then holds whatever it produced first.
    pub error: Option<ShapeError>,
}

impl Shaped {
    /// The lines to print on stderr, each prefixed `wires: `: the notes,
    /// then the error if any.
    pub fn stderr_lines(&self) -> Vec<String> {
        self.notes
            .iter()
            .cloned()
            .chain(self.error.iter().map(|e| format!("wires: {e}")))
            .collect()
    }
}

impl Shape {
    /// Validate `args` into a [`Shape`]; a bad jq filter is an error here,
    /// before any call is made.
    pub fn new(args: &ShapeArgs) -> Result<Self, ShapeError> {
        Ok(Self {
            jq: args.jq.as_deref().map(JqProgram::new).transpose()?,
            head: args.head,
            max_bytes: args.max_bytes,
        })
    }

    /// True when no stage is set: the output can stream straight through.
    pub fn is_identity(&self) -> bool {
        self.jq.is_none() && self.head.is_none() && self.max_bytes.is_none()
    }

    /// Apply the stages, in order, to the remote `stdout`.
    pub fn apply(&self, stdout: &[u8]) -> Shaped {
        let mut shaped = Shaped::default();
        let mut bytes = match &self.jq {
            Some(p) => {
                let (out, err) = p.run(stdout);
                shaped.error = err;
                out
            }
            None => stdout.to_vec(),
        };
        if let Some(n) = self.head {
            bytes.truncate(head_len(&bytes, n));
        }
        if let Some(n) = self.max_bytes
            && bytes.len() > n
        {
            let cut = char_floor(&bytes, n);
            shaped.notes.push(format!(
                "wires: stdout truncated to {cut} of {} bytes (--max-bytes {n})",
                bytes.len()
            ));
            bytes.truncate(cut);
        }
        shaped.stdout = bytes;
        shaped
    }
}

/// The exit code for a shaped call: the remote code if it failed (never
/// masked), else [`EXIT_SHAPE`] if shaping failed, else 0.
pub fn exit_code(remote: i32, shaped: &Shaped) -> i32 {
    match (remote, &shaped.error) {
        (0, Some(_)) => EXIT_SHAPE,
        (code, _) => code,
    }
}

/// Length of the first `n` lines of `bytes` (each keeping its `\n`).
/// `\n` is ASCII, so the cut never lands inside a UTF-8 character.
pub fn head_len(bytes: &[u8], n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    bytes
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .nth(n - 1)
        .map_or(bytes.len(), |(i, _)| i + 1)
}

/// The largest cut `<= n` that doesn't split a UTF-8 character: step back
/// over continuation bytes (`10xxxxxx`), at most three, since no encoded
/// character is longer than four bytes. Invalid UTF-8 is cut at `n`.
pub fn char_floor(bytes: &[u8], n: usize) -> usize {
    if n >= bytes.len() {
        return bytes.len();
    }
    let mut cut = n;
    while cut > 0 && n - cut < 3 && bytes[cut] & 0xC0 == 0x80 {
        cut -= 1;
    }
    if bytes[cut] & 0xC0 == 0x80 { n } else { cut }
}

/// Parse and compile `src`, then hand the filter to `f`.
fn with_filter<T>(
    src: &str,
    f: impl FnOnce(&jaq_core::compile::Filter<jaq_core::Native<data::JustLut<Val>>>) -> T,
) -> Result<T, ShapeError> {
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());
    let arena = Arena::default();
    let modules = Loader::new(defs)
        .load(
            &arena,
            File {
                code: src,
                path: (),
            },
        )
        .map_err(|errs| compile_error(src, load_messages(errs)))?;
    let filter = Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|errs| {
            let msgs = errs
                .into_iter()
                .flat_map(|(_, es)| es)
                .map(|(name, undefined)| format!("undefined {} `{name}`", undefined.as_str()))
                .collect();
            compile_error(src, msgs)
        })?;
    Ok(f(&filter))
}

/// Messages for jaq's lex and parse errors: what it expected, and where.
fn load_messages<P>(errs: jaq_core::load::Errors<&str, P>) -> Vec<String> {
    use jaq_core::load::Error;
    let at = |rest: &str| {
        if rest.is_empty() {
            "at the end".to_owned()
        } else {
            format!("at `{}`", rest.chars().take(20).collect::<String>())
        }
    };
    errs.into_iter()
        .flat_map(|(_, e)| match e {
            Error::Io(v) => v
                .into_iter()
                .map(|(path, msg)| format!("cannot import `{path}`: {msg}"))
                .collect::<Vec<_>>(),
            Error::Lex(v) => v
                .into_iter()
                .map(|(expect, rest)| format!("expected {} {}", expect.as_str(), at(rest)))
                .collect(),
            Error::Parse(v) => v
                .into_iter()
                .map(|(expect, rest)| format!("expected {} {}", expect.as_str(), at(rest)))
                .collect(),
        })
        .collect()
}

fn compile_error(src: &str, msgs: Vec<String>) -> ShapeError {
    ShapeError(format!(
        "--jq: invalid filter `{src}`: {}",
        if msgs.is_empty() {
            "does not compile".to_owned()
        } else {
            msgs.join("; ")
        }
    ))
}

fn not_json(input: &[u8], why: &str) -> ShapeError {
    let cut = char_floor(input, SNIPPET_BYTES);
    let more = if cut < input.len() { "…" } else { "" };
    ShapeError(format!(
        "--jq: the remote stdout is not JSON ({why}); it begins: {:?}{more}",
        String::from_utf8_lossy(&input[..cut])
    ))
}

/// One jq output, `gh --jq` style: a string raw, anything else compact JSON.
fn render(v: &Val, out: &mut Vec<u8>) {
    match v {
        Val::TStr(b) | Val::BStr(b) => out.extend_from_slice(b),
        other => out.extend_from_slice(other.to_string().as_bytes()),
    }
    out.push(b'\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn jq(src: &str, input: &str) -> (String, Option<ShapeError>) {
        let (out, err) = JqProgram::new(src).unwrap().run(input.as_bytes());
        (String::from_utf8(out).unwrap(), err)
    }

    fn shape(jq: Option<&str>, head: Option<usize>, max_bytes: Option<usize>) -> Shape {
        Shape::new(&ShapeArgs {
            jq: jq.map(str::to_owned),
            head,
            max_bytes,
        })
        .unwrap()
    }

    #[test]
    fn jq_prints_strings_raw_and_the_rest_compact() {
        let input =
            r#"{"tagName":"v2.1.0","files":[{"filename":"a.rs"},{"filename":"b.rs"}],"n":3}"#;
        assert_eq!(jq(".tagName", input).0, "v2.1.0\n");
        assert_eq!(jq(".files[].filename", input).0, "a.rs\nb.rs\n");
        assert_eq!(jq(".n", input).0, "3\n");
        assert_eq!(jq("{n}", input).0, "{\"n\":3}\n");
        assert_eq!(
            jq("[.files[] | .filename]", input).0,
            "[\"a.rs\",\"b.rs\"]\n"
        );
    }

    #[test]
    fn jq_has_the_std_library_gh_users_reach_for() {
        let input = r#"[{"t":"bug fix","c":3},{"t":"feat","c":9}]"#;
        assert_eq!(jq("map(select(.c > 5)) | length", input).0, "1\n");
        assert_eq!(jq("sort_by(.c) | reverse | .[0].t", input).0, "feat\n");
        assert_eq!(
            jq(r#"[.[] | select(.t | test("bug"))] | length"#, input).0,
            "1\n"
        );
        assert_eq!(
            jq(r#""2026-09-01T00:00:00Z" | fromdateiso8601"#, "null").0,
            "1788220800\n"
        );
        assert_eq!(jq(r#".[0] | "\(.t): \(.c)""#, input).0, "bug fix: 3\n");
    }

    #[test]
    fn jq_reads_every_value_in_a_stream() {
        assert_eq!(jq(".a", "{\"a\":1}\n{\"a\":2}\n").0, "1\n2\n");
    }

    #[test]
    fn invalid_filter_is_a_clear_error() {
        for bad in [".[", "map(", "nosuchfn", ".a |"] {
            let e = JqProgram::new(bad).unwrap_err();
            assert!(
                e.message().starts_with("--jq: invalid filter"),
                "{bad}: {e}"
            );
            assert!(e.message().contains(bad), "{bad}: {e}");
        }
        assert!(
            JqProgram::new("nosuchfn")
                .unwrap_err()
                .message()
                .contains("nosuchfn")
        );
        let e = Shape::new(&ShapeArgs {
            jq: Some(".[".into()),
            ..Default::default()
        })
        .unwrap_err();
        assert!(e.message().contains("invalid filter"));
    }

    #[test]
    fn non_json_input_is_an_error_that_quotes_it() {
        let (out, err) = jq(".", "HTTP 404: Not Found");
        assert!(out.is_empty());
        let e = err.unwrap();
        assert!(e.message().contains("not JSON"), "{e}");
        assert!(e.message().contains("HTTP 404"), "{e}");
    }

    #[test]
    fn runtime_error_keeps_the_output_before_it() {
        let (out, err) = jq(".[] | .a", r#"[{"a":1}, 5]"#);
        assert_eq!(out, "1\n");
        assert!(err.unwrap().message().starts_with("--jq:"));
    }

    #[test]
    fn head_keeps_n_lines() {
        let s = shape(None, Some(2), None);
        assert_eq!(s.apply(b"a\nb\nc\n").stdout, b"a\nb\n");
        assert_eq!(s.apply(b"a\nb").stdout, b"a\nb");
        assert_eq!(s.apply(b"").stdout, b"");
        assert_eq!(shape(None, Some(0), None).apply(b"a\n").stdout, b"");
    }

    #[test]
    fn max_bytes_cuts_on_a_char_boundary_with_a_note() {
        let s = shape(None, None, Some(4));
        let shaped = s.apply("aé€x".as_bytes()); // 1 + 2 + 3 + 1 bytes
        assert_eq!(shaped.stdout, "aé".as_bytes());
        assert_eq!(
            shaped.notes,
            ["wires: stdout truncated to 3 of 7 bytes (--max-bytes 4)"]
        );
        assert!(s.apply(b"abcd").notes.is_empty());
    }

    #[test]
    fn stages_run_jq_then_head_then_max_bytes() {
        let s = shape(Some(".[]"), Some(2), Some(5));
        let shaped = s.apply(br#"["alpha","beta","gamma"]"#);
        assert_eq!(shaped.stdout, b"alpha");
        assert!(shaped.error.is_none());
        assert!(shape(None, None, None).is_identity());
        assert!(!s.is_identity());
    }

    #[test]
    fn remote_exit_code_is_never_masked() {
        let ok = Shaped::default();
        let failed = Shaped {
            error: Some(ShapeError("x".into())),
            ..Default::default()
        };
        assert_eq!(exit_code(0, &ok), 0);
        assert_eq!(exit_code(0, &failed), EXIT_SHAPE);
        assert_eq!(exit_code(1, &failed), 1);
        assert_eq!(exit_code(4, &ok), 4);
    }

    fn arb_json() -> impl Strategy<Value = serde_json::Value> {
        let leaf = prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::from),
            any::<i64>().prop_map(serde_json::Value::from),
            "\\PC{0,12}".prop_map(serde_json::Value::from),
        ];
        leaf.prop_recursive(4, 32, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(serde_json::Value::from),
                prop::collection::btree_map("[a-z]{1,6}", inner, 0..6)
                    .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        /// `.` over arbitrary JSON gives back the same value; `tojson` of it
        /// parses to the same value; `length`-style filters never error.
        #[test]
        fn jq_identity_round_trips_arbitrary_json(v in arb_json()) {
            let input = serde_json::to_vec(&v).unwrap();
            let (out, err) = JqProgram::new(".").unwrap().run(&input);
            prop_assert!(err.is_none());
            let out = String::from_utf8(out).unwrap();
            if let serde_json::Value::String(s) = &v {
                // A top-level string prints raw, like `gh --jq`.
                prop_assert_eq!(out, format!("{s}\n"));
            } else {
                let back: serde_json::Value = serde_json::from_str(out.trim_end()).unwrap();
                prop_assert_eq!(back, v.clone());
            }
            let (_, err) = JqProgram::new("[.. | type] | length").unwrap().run(&input);
            prop_assert!(err.is_none());
        }

        /// `--head` never splits a character and keeps a prefix.
        #[test]
        fn head_never_splits_a_char(s in "\\PC{0,40}(\n\\PC{0,20}){0,6}", n in 0usize..8) {
            let out = shape(None, Some(n), None).apply(s.as_bytes()).stdout;
            let out = String::from_utf8(out).expect("valid UTF-8");
            prop_assert!(s.starts_with(&out));
            prop_assert!(out.matches('\n').count() <= n);
        }

        /// `--max-bytes` never splits a character, never exceeds N, and
        /// notes exactly when it cut.
        #[test]
        fn max_bytes_never_splits_a_char(s in "\\PC{0,64}", n in 0usize..80) {
            let shaped = shape(None, None, Some(n)).apply(s.as_bytes());
            prop_assert!(shaped.stdout.len() <= n);
            let out = String::from_utf8(shaped.stdout).expect("valid UTF-8");
            prop_assert!(s.starts_with(&out));
            // Short by less than one char (at most 3 bytes) when it cut.
            prop_assert!(out.len() + 3 >= n.min(s.len()));
            prop_assert_eq!(shaped.notes.is_empty(), s.len() <= n);
        }

        /// On arbitrary bytes (not just UTF-8), the cut stays within bounds.
        #[test]
        fn char_floor_is_bounded(b in prop::collection::vec(any::<u8>(), 0..64), n in 0usize..80) {
            let cut = char_floor(&b, n);
            prop_assert!(cut <= n.min(b.len()));
            prop_assert!(cut + 3 >= n.min(b.len()));
        }
    }
}
