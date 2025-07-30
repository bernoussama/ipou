# AGENTS.md

## Build/Test Commands
- `cargo build` - Build the project
- `cargo run` - Run the main binary
- `cargo test` - Run all tests
- `cargo test <test_name>` - Run a specific test
- `cargo test -- --test-threads=1` - Run tests sequentially (for network tests)
- `cargo check` - Fast compile check without building
- `cargo clippy` - Run linter

## Code Style Guidelines

### Imports
- Group imports: std first, external crates, then local modules
- Use `use crate::` for local imports from lib root
- Use `use trustun::` for importing from this crate (project name: trustun)

### Formatting
- Use `rustfmt` defaults (4-space indentation, snake_case)
- Max line length: 100 characters (rustfmt default)

### Types & Naming
- Use `snake_case` for functions, variables, modules
- Use `PascalCase` for structs, enums, traits
- Use descriptive names for variables and functions
- Constants in `SCREAMING_SNAKE_CASE` (see lib.rs for examples)

### Error Handling
- Use `thiserror` for custom error types with `#[error]` attribute
- Define project `Result<T>` type alias for `std::result::Result<T, IpouError>`
- Use `?` operator for error propagation
- Add `#[from]` attribute for automatic error conversion in IpouError enum

### Async/Concurrency
- Use `tokio` for async runtime and utilities
- Use `Arc<RwLock<T>>` for shared mutable state across tasks
- Use `mpsc` channels for task communication
- Spawn tasks with descriptive names using `tokio::spawn`