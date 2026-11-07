#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod bitfield;
pub mod core;
pub mod crypto;
pub mod encryption;
pub mod flat_tree;
pub mod merkle;
pub mod remote_bitfield;
pub mod replicator;
pub mod storage;
pub mod verifier;
mod wants;

pub use compact_encoding::hypercore::{Manifest, Node};
pub use core::{
    AppendOptions, Core, CoreError, CoreEvent, CoreOptions, GetOptions, GroupUpdate, Head,
    RequestBag, Session,
};
