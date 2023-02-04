APP=tracekill

.PHONY: build
build: gen $(APP)

.PHONY: run
run: build
	sudo ./$(APP)

.PHONY: gen
gen: sum  gen_endian

.PHONY: vmlinux
vmlinux: src/headers/vmlinux.h

.PHONY: sum
sum: go.sum

.PHONY: gen_endian
gen_endian:
	go generate src/*.go

.PHONY: fmt
fmt: sum
	go fmt src/*.go

.PHONY: clean
clean:
	-rm $(APP)
	-rm src/bpf_bpfe*
	-rm go.sum
$(APP): src/main.go src/bpf_bpfel.go
	# to generate  little endian binary
	go build -o $(APP) src/main.go src/bpf_bpfel.go
	#to generate big endian binary
	#go build -o $(APP)_b src/main.go src/bpf_bpfeb.go

src/headers/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/headers/vmlinux.h

go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/cilium/ebpf/internal/unix
