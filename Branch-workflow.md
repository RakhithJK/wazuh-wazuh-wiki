- The main branch is `master`. That stores the deployable code and has the version of the next major-minor release.
- Branches `x.y` (like `3.13` or `4.0`) hold the stable and release candidate code.

## Development branches

- Name: `dev-N-...` where N is the number of the related issue.
- They start from `master` and are merged into `master`.

### Sub-branches

- We may create sub-branches starting from development branches.
- We must merge those branches into the same branch via PR.

## Patch branches

- Name: `fix-N-...` where N is the number of the related issue.
- They start from the last stable branch (`x.y`) and are merged into the same branch.

## Release protocol

1. Prepare the branch.
   - Major-minor version:
      1. Freeze the branch `master` into a new branch `x.y`.
      2. Bump the version of the branch `master` to the next major-minor version.
      3. Tag `vX.Y.Z-rc1`.
   - Patch version:
      1. Bump the version of the branch `x.y` to the next patch version.
2. While necessary, accept patch PRs into `x.y` and tag as `vX.Y.Z-rcN`.
3. Tag branch `x.y` as `vX.Y.Z`.
4. Merge branch `x.y` into `master`.