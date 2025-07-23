#[derive(thiserror::Error, Debug)]
pub enum IpouError {
    #[error("An unknown error occurred: {0}")]
    Unknown(String),
}

pub type Result<T> = std::result::Result<T, IpouError>;
