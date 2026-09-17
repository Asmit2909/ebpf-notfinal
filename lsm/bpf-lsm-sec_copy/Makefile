.PHONY: generate build run clean

generate:
	cd pkg/bpf && PATH="/snap/bin:$$PATH" go generate

build: generate
	@if [ -d dependencies ]; then mv dependencies vendor; fi
	PATH="/snap/bin:$$PATH" go build -mod=vendor -o bpf-sec-daemon ./cmd/bpf-sec-daemon
	@if [ -d vendor ]; then mv vendor dependencies; fi

run: build
	sudo ./bpf-sec-daemon

clean:
	rm -f bpf-sec-daemon pkg/bpf/bpf_*.go pkg/bpf/bpf_*.o
