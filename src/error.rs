#[derive(thiserror::Error, Debug)]
pub enum IpouError {}

pub type Result<T> = std::result::Result<T, IpouError>;
