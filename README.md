# distributed-fs-caching-model
Distributed File System - Upload/Download Model

### Description
An extension of the remote access distributed system project that adds client side caching, timeout-based validation, atomic file transfers, and write-exclusion for high-performance and consistent access

This upload/download model caches files locally in a client directory and only fetches from (or pushes changes to) the server when needed. It implements timeout based freshness checks, mutual exclusion for concurrent writers, and atomic transfers to ensure clients always see a consistent view of each file.

### Key Features
1. Local Caching directory - for downloaded files and metadata
2. Time out based freshness checks - revalidate cache on reads/writes after a configurable interval
3. Atomic upload/download to avoid seeing partial updates
4. Read/Write Exclusion - multiple concurrent readers allowed, single writer enforced
5. Automaic write-back on fsync and file close to guarantee durability
