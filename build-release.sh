cargo build --target x86_64-unknown-linux-musl -r 
cross build --target aarch64-unknown-linux-musl -r

cp target/x86_64-unknown-linux-musl/release/quarterback target/quarterback-x86_64
cp target/aarch64-unknown-linux-musl/release/quarterback target/quarterback-aarch64

sha256sum target/quarterback* > target/quarterback.sha256
