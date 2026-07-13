test:
	@cargo build --release
	@sudo setcap cap_net_bind_service=+ep ./target/release/dns-hijacker
	@./target/release/dns-hijacker

