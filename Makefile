.PHONY: nsm, console
nsm:
	docker build -t nsm -f Dockerfile.nsm .
	nitro-cli build-enclave --docker-uri nsm:latest --output-file nsm.eif
	nitro-cli terminate-enclave --all
	nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 16 --eif-path nsm.eif --debug-mode

console:
	nitro-cli console --enclave-id $(shell nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
