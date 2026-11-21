#undef NDEBUG
#include <cassert>
#include <cmath>
#include <stdexcept>
#include <thread>

#include "proculus/timing/rate.hpp"

using namespace proculus;

static bool near(double a, double b, double eps = 1e-6) { return std::fabs(a - b) <= eps * (1 + std::fabs(b)); }

static void test_ewma() {
	RateEstimator r(0.5);
	assert(!r.has_estimate() && r.rate() == 0 && r.samples() == 0);
	assert(!r.estimate_seconds(100) && !r.addresses_for(10));

	r.record(1000, 10); // 100/s: first sample is taken as is
	assert(near(r.rate(), 100) && r.samples() == 1);
	r.record(3000, 10); // 300/s -> 0.5*300 + 0.5*100 = 200
	assert(near(r.rate(), 200));
	r.record(2000, 10); // 200/s -> unchanged
	assert(near(r.rate(), 200) && r.samples() == 3);

	assert(near(*r.estimate_seconds(1000), 5));
	assert(*r.addresses_for(60) == 12000);
	assert(*r.addresses_for(0.001) == 1); // never zero
	assert(!r.addresses_for(0) && !r.addresses_for(-5));
}

static void test_ignores_useless_samples() {
	RateEstimator r;
	r.record(0, 10);
	r.record(100, 0);
	r.record(100, -1);
	r.record(100, std::nan(""));
	r.record(100, INFINITY);
	assert(!r.has_estimate() && r.samples() == 0);
}

static void test_prior() {
	RateEstimator r(0.3, 50);
	assert(r.has_estimate() && near(r.rate(), 50) && r.samples() == 0);
	assert(near(*r.estimate_seconds(500), 10));
	r.record(1000, 5); // first real measurement replaces the prior
	assert(near(r.rate(), 200));

	assert(RateEstimator(1.0, 0).rate() == 0);
	bool threw = false;
	try { RateEstimator(0.0); } catch (const std::invalid_argument&) { threw = true; }
	assert(threw);
	threw = false;
	try { RateEstimator(1.5); } catch (const std::invalid_argument&) { threw = true; }
	assert(threw);
}

static void test_adapts() {
	RateEstimator r(0.3);
	for (int i = 0; i < 5; i++) r.record(1000, 10); // 100/s
	for (int i = 0; i < 30; i++) r.record(1000, 100); // network slows to 10/s
	assert(r.rate() < 11 && r.rate() > 9.9);
}

static void test_serialize() {
	RateEstimator r(0.3);
	r.record(1234, 7);
	r.record(999, 3);
	RateEstimator copy(0.3);
	assert(copy.restore(r.serialize()));
	assert(near(copy.rate(), r.rate(), 1e-6) && copy.samples() == 2);

	RateEstimator keep(0.3, 42);
	for (const char* bad : {"", "abc", "10", "10;", "10;x", "-5;3", "10;-1", "nan;1", "inf;1", "10;3x"})
		assert(!keep.restore(bad));
	assert(near(keep.rate(), 42) && keep.samples() == 0); // unchanged after failures
}

static void test_table_and_progress() {
	RateTable t;
	t.stage("discovery").record(10000, 10);
	t.stage("services").record(100, 10);
	assert(near(t.stage("discovery").rate(), 1000) && near(t.stage("services").rate(), 10));
	assert(t.find("http") == nullptr && t.find("discovery") != nullptr);

	Progress p{1000, 400};
	assert(p.remaining() == 600 && near(p.fraction(), 0.4));
	assert(near(*eta_seconds(p, t.stage("discovery")), 0.6));
	assert((Progress{0, 0}.fraction() == 1.0));
	assert((Progress{10, 20}.remaining() == 0));
	assert(!eta_seconds(p, RateEstimator()));
}

static void test_stopwatch() {
	Stopwatch s;
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	double e = s.elapsed_seconds();
	assert(e >= 0.04 && e < 2.0);
	s.restart();
	assert(s.elapsed_seconds() < e);
}

int main() {
	test_ewma();
	test_ignores_useless_samples();
	test_prior();
	test_adapts();
	test_serialize();
	test_table_and_progress();
	test_stopwatch();
	return 0;
}
