help:
	@echo "perf_event_tests (perf fuzzer)"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  test 		# run the API tests and ~5 minute fuzz test"
	@echo "  longfuzz 	# run ~30 minute fuzz test"

tarball = perf_event_tests.tar.gz

download: $(tarball)

$(tarball):
	wget --no-verbose -O $@.tmp https://github.com/deater/perf_event_tests/tarball/master
	mv $@.tmp $@

prepare: download
	@./install-deps.sh

perf_event_tests: $(tarball)
	@./install-deps.sh
	+@./build.sh

build: perf_event_tests

test: perf_event_tests
	+@./test.sh api-test 5m

shortfuzz: perf_event_tests
	+@./test.sh - 2m

longfuzz: perf_event_tests
	+@./test.sh - 30m

clean:
	rm -rf perf_event_tests log

distclean: clean
	rm -f $(tarball)

.PHONY: download prepare build test clean distclean help longfuzz
