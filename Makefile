# Requires opa and conftest on PATH. `make all` is what CI runs.
POLICY := policy
TESTS  := tests
MIN_COVERAGE := 100

.PHONY: all lint test coverage examples traceability traceability-check scan

all: lint coverage examples traceability-check

lint:
	opa fmt --fail -l $(POLICY) $(TESTS)
	opa check --strict $(POLICY) $(TESTS)

test:
	opa test $(POLICY) $(TESTS) -v

coverage:
	opa test $(POLICY) $(TESTS) --coverage --threshold $(MIN_COVERAGE) > /dev/null
	@echo "coverage >= $(MIN_COVERAGE)%"

examples:
	python3 scripts/verify_examples.py

traceability:
	python3 scripts/traceability.py

traceability-check:
	python3 scripts/traceability.py --check

# Scan any SA database: make scan FILE=path/to/mission.sdls.yaml
scan:
	conftest test $(FILE) -p $(POLICY) --all-namespaces
