build_attest:
	@echo "Building attest..."
	docker build -t attest .
	@echo "Building enclave image..."
	nitro-cli build-enclave --docker-uri attest:latest --output-file attest.eif
	@echo "Starting enclave instance..."
	nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 16 --eif-path attest.eif --debug-mode
	nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
