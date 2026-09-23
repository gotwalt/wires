# Benchmark tasks

Five read-only tasks on public repositories. The exact prompt text lives in
`bench.py` (`TASKS`); every arm gets the same text. The CLI arms get one
extra leading line saying how to reach `gh`. Every prompt ends with a
required `ANSWER:` line format, so answers can be scored automatically.

Ground truth comes from the GitHub REST API (`gh api`) at the start and end
of each repetition. A run counts as correct if it matches either snapshot.

| id | question | truth source | scoring |
|---|---|---|---|
| t1-release | Latest release of `cli/cli`: tag and publication date (UTC). | `repos/cli/cli/releases/latest` | the tag and the `YYYY-MM-DD` date both appear |
| t2-merged-prs | The 3 most recently merged PRs in `modelcontextprotocol/modelcontextprotocol`, by merge time. | closed PRs, sorted by `merged_at` | the set of 3 numbers matches (order not checked) |
| t3-bug-count | Number of open issues (not PRs) labelled `bug` in `anthropics/claude-code`. | search `is:issue is:open label:bug` `total_count` | within ±max(3, 1%) (the count moves during a run) |
| t4-commit-files | Files changed by commit `b5a6860d964e6b394ddfd8cdb0a2f14fbb22ab21` in `sharkdp/hyperfine`. | `repos/.../commits/<sha>` | exact set of 4 paths |
| t5-most-commented | Open issue with the most comments in `cli/cli`; who wrote its latest comment, plus a one-sentence summary. | search `sort:comments-desc`, then the last page of comments | issue number and last commenter's login (`[bot]` suffix ignored); the summary isn't scored |

Why these tasks: each is a question an agent actually gets asked. Together
they cover a single lookup (t1, t4), a list with ordering (t2), a count that
is easy to get wrong by paginating instead of searching (t3), and a two-step
lookup that reads a long thread (t5, 146 comments). t1 and t5 also exercise
large responses: a release body, and a comment thread.
