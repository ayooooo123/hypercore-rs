//! Storage for hypercore: npm `hypercore-storage`'s RocksDB layout, read and
//! written through [`hypercore_storage`].
//!
//! One directory is one RocksDB with a `corestore` column family; every core is
//! a row plus a data pointer. This module re-exports the backend so existing
//! call sites keep their names (`Store`, `CoreStorage`, `Batch`, `StorageError`).

pub use hypercore_storage::{
    Alias, Auth, CoreGroup, CoreHead, CoreStorage, CoreTx as Batch, CreateCore,
    Error as StorageError, Hints as HeaderHints, InfoOptions, KeyPair, Node, Store,
};
