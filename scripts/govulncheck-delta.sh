#!/usr/bin/env bash
#
# Report vulnerabilities that are REACHABLE FROM THIS CODE and that a change
# introduces, by scanning two refs in one process.
#
# Why two refs, in one run:
#
#   govulncheck queries the live vulnerability database. A base result cached
#   from an earlier run is therefore not comparable with a head result produced
#   now -- the difference between them would include every advisory published in
#   between, and the gate would report findings the change did not cause. Both
#   scans happen here, seconds apart, against the same snapshot.
#
# Why the delta rather than the absolute count:
#
#   An advisory published today can make a pull request red without its author
#   having touched anything. A check that does that gets called flaky and then
#   gets switched off. Gating on what the change ADDS removes that failure mode
#   instead of trading against it. Database drift is real and still needs
#   answering -- it belongs to the scheduled run on main (--scan), not here.
#
# Usage:
#   govulncheck-delta.sh <base-ref> <head-ref>   compare two refs, report additions
#   govulncheck-delta.sh --scan <ref>            list what is reachable at one ref
#
# Exit status:
#   0  no additions (or --scan, which never fails on findings)
#   1  additions found AND GOVULNCHECK_BLOCK=1
#   2  usage or environment error
#
# GOVULNCHECK_BLOCK is off by default on purpose: this gate has no track record
# in this repository yet, and a blocking check whose behaviour nobody has watched
# is worse than no check, because it is trusted without being looked at. Turn it
# on once it has run for two weeks without a false positive.
#
# TURNING IT ON IS TWO CHANGES, NOT ONE. Pin GOVULNCHECK_VERSION in the same
# commit that sets GOVULNCHECK_BLOCK=1.
#
# A floating `latest` is right while this only reports: the newest advisory data
# is what you want, and base and head share one process, so both sides see the
# same tool and the delta stays consistent. Once it blocks, that same float is a
# tool upgrade that can stop CI on a day no commit in this repository changed
# anything — and nothing in git says what moved, so nobody can find it. The
# variable already exists; only its default has to change.

set -euo pipefail

GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-latest}"
GOVULNCHECK_BLOCK="${GOVULNCHECK_BLOCK:-0}"

usage() {
  echo "usage: $0 <base-ref> <head-ref>" >&2
  echo "       $0 --scan <ref>" >&2
  exit 2
}

# reachable_ids <worktree-dir>
#
# Prints the sorted OSV ids that this code actually CALLS, one per line.
#
# The filter is the whole point. govulncheck reports a finding for every
# advisory against a module in the graph, and separately for the subset our code
# reaches; the text output describes the difference as "your code doesn't appear
# to call these". Both kinds arrive as `finding` records, so comparing raw osv
# ids gates on the module-level set -- far larger, and mostly advisories against
# dependencies nobody calls. A finding is reachable when the first frame of its
# trace names a `function`; module-level findings have none.
#
# `-format json` exits 0 whether or not anything is found -- unlike the text
# mode, which exits 3 on findings. So the exit status here means "the scan ran",
# never "the tree is clean", and nothing downstream may read it as the latter.
reachable_ids() {
  local dir="$1" out="$2"

  if ! (cd "$dir" && GOFLAGS=-mod=mod go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" \
        -format json ./... > "$out" 2>"${out}.err"); then
    echo "govulncheck failed in ${dir}:" >&2
    tail -20 "${out}.err" >&2
    exit 2
  fi

  jq -r 'select(.finding != null)
         | select(.finding.trace[0].function != null)
         | .finding.osv' < "$out" | sort -u
}

# scan_ref <ref> <label>
#
# Scans a ref in its own worktree, so neither side depends on the state of the
# checkout this runs from and the two scans cannot contaminate each other.
scan_ref() {
  local ref="$1" label="$2" wt json started elapsed
  wt="$(mktemp -d)"
  json="$(mktemp)"

  git worktree add --detach -q "$wt" "$ref"
  started="$SECONDS"
  reachable_ids "$wt" "$json"
  elapsed="$(( SECONDS - started ))"
  echo "scanned ${label} (${ref}) in ${elapsed}s" >&2

  git worktree remove --force "$wt"
  rm -f "$json" "${json}.err"
}

main() {
  command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }

  if [[ "${1:-}" == "--scan" ]]; then
    [[ $# -eq 2 ]] || usage
    scan_ref "$2" "ref"
    return 0
  fi

  [[ $# -eq 2 ]] || usage

  local base_ids head_ids added
  base_ids="$(scan_ref "$1" "base")"
  head_ids="$(scan_ref "$2" "head")"

  # comm needs sorted input and both sides may legitimately be empty, which is
  # why they are passed as process substitutions of already-sorted output rather
  # than files that might not exist.
  added="$(comm -13 <(echo "$base_ids") <(echo "$head_ids") | grep -v '^$' || true)"

  echo "base reachable: $(echo "$base_ids" | grep -c '[^[:space:]]' || true)"
  echo "head reachable: $(echo "$head_ids" | grep -c '[^[:space:]]' || true)"

  if [[ -z "$added" ]]; then
    echo "no vulnerability reachable from this code was introduced by this change"
    return 0
  fi

  echo ""
  echo "introduced by this change:"
  while IFS= read -r id; do
    echo "  ${id}"
  done <<< "$added"
  echo ""
  echo "https://pkg.go.dev/vuln/ carries the details for each id."

  if [[ "$GOVULNCHECK_BLOCK" == "1" ]]; then
    return 1
  fi
  echo ""
  echo "reporting only: GOVULNCHECK_BLOCK is not set."
  return 0
}

main "$@"
