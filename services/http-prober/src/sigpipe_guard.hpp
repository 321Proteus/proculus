#ifndef PROCULUS_SIGPIPE_GUARD_HPP
#define PROCULUS_SIGPIPE_GUARD_HPP

#include <pthread.h>
#include <signal.h>

#include <ctime>

namespace proculus {

// Keeps SIGPIPE from killing the process while this thread talks to the network.
//
// Writing to a connection the peer has already closed raises SIGPIPE, whose
// default action is to terminate the whole program. A scanner meets servers
// that slam connections shut, so that must be an error return instead. Plain
// send() can ask for no signal (MSG_NOSIGNAL), but TLS writes go through
// OpenSSL, which cannot. Blocking the signal on this thread for the duration
// of the exchange covers both; a signal that was raised meanwhile is discarded
// before the mask is restored. (Where sigtimedwait does not exist, as on macOS,
// sockets carry SO_NOSIGPIPE instead and no signal is ever raised.)
class SigpipeGuard {
public:
	SigpipeGuard() {
		sigset_t pipe_only;
		sigemptyset(&pipe_only);
		sigaddset(&pipe_only, SIGPIPE);
		pthread_sigmask(SIG_BLOCK, &pipe_only, &old_);
	}

	~SigpipeGuard() {
#ifdef __linux__
		sigset_t pipe_only;
		sigemptyset(&pipe_only);
		sigaddset(&pipe_only, SIGPIPE);
		const timespec no_wait{0, 0};
		while (sigtimedwait(&pipe_only, nullptr, &no_wait) > 0) {
		}
#endif
		pthread_sigmask(SIG_SETMASK, &old_, nullptr);
	}

	SigpipeGuard(const SigpipeGuard&) = delete;
	SigpipeGuard& operator=(const SigpipeGuard&) = delete;

private:
	sigset_t old_;
};

} // namespace proculus

#endif // PROCULUS_SIGPIPE_GUARD_HPP
