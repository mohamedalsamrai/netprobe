//! The four probes of section 4. Each one generates its own traffic and turns it into
//! measurement data; scheduling and storage live in the agent.

pub mod connection;
pub mod dns;
pub mod icmp;
pub mod latency;
pub mod net;
pub mod rt;
pub mod throughput;
