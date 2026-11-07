# Read-only Release Source-Map Inspection

```sh
aegis inspect-release ./dist --json
```

The `inspectReleaseExposure(target)` library API and `inspect-release` CLI command observe local release files without modifying them, fetching references, running bundles, or reading source paths named by maps.
