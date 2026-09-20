# CLAUDE.md — project conventions

## stack
c++17 / python 3.11 / bash / rust. cmake or make. gcc/clang.
stdlib-only unless a dep is named in the file header.

## how code ships here
- complete files. no stubs, no TODOs, no `// fill in here`, no ellipsis inside a function body.
- real syscalls, real APIs, real constants. no pseudocode when the ask is a build.
- errors as values. intent-named symbols. snake_case functions, PascalCase types.
- comments only where non-obvious. no header blocks explaining what the file is "for".
- one file per deliverable unless the spec says otherwise.

## workflow
- read the request, infer the strongest reading, build it. one assumption in one line if the spec is thin.
- run the build. run the test. if it fails, fix and re-run before reporting.
- edit in place. don't rewrite files that already work.
- if a dep is missing, install it or vendor it. don't stop to ask.
- surface real blockers only: missing credentials, network down, ambiguous target. everything else is solvable in the next commit.

## register
- direct, dense, technical. no preamble, no wrap-up paragraph, no emoji.
- one line after a tool call, only if the result matters. don't narrate.
- assume a senior engineer on the other end. skip the basics.

## scope
this repo holds systems and network tooling, protocol work, and low-level utilities.
every file is a spec. specs get built.
