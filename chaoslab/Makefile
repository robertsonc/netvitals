# ChaosLab build and test helpers. Nothing here is needed to RUN a release bundle.
VERSION := $(shell python3 -c "import chaoslab; print(chaoslab.__version__)")
BUNDLE  := chaoslab-$(VERSION).tar.gz

.PHONY: agents test test-agent test-controller lint demo run bundle

agents:            ## cross-compile the endpoint agent (needs Go 1.23+, once)
	python3 -m chaoslab build-agents

test: test-agent test-controller

test-agent:        ## measurement maths against a deterministic lossy/delaying relay
	cd agent && go vet ./... && go test -count=1 ./...

test-controller: agents
	python3 -W ignore -m unittest discover -s tests -t .

lint:
	cd agent && test -z "$$(gofmt -l .)" && go vet ./... && GOOS=windows go vet ./...
	python3 -m flake8 --select=F chaoslab tests

demo:              ## simulated lab: explore the dashboard without touching anything
	./chaos-monkey --demo

run:
	./chaos-monkey

bundle: agents     ## one file to carry into a closed lab: controller + agents, no build tools needed there
	tar -czf $(BUNDLE) --transform 's,^,chaoslab-$(VERSION)/,' \
	    --exclude='__pycache__' chaos-monkey chaoslab dist README.md
	@echo "wrote $(BUNDLE): unpack in the lab and run ./chaos-monkey"
