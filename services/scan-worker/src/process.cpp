#include "process.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace proculus {

namespace {

using Clock = std::chrono::steady_clock;

void set_nonblocking(int fd) {
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

// Drains what is readable; returns false once the pipe hit EOF.
bool drain(int fd, std::string& into, size_t limit, bool* truncated) {
	char buf[65536];
	for (;;) {
		ssize_t n = read(fd, buf, sizeof buf);
		if (n > 0) {
			if (into.size() + static_cast<size_t>(n) > limit) {
				into.append(buf, limit > into.size() ? limit - into.size() : 0);
				if (truncated) *truncated = true;
			} else {
				into.append(buf, static_cast<size_t>(n));
			}
			continue;
		}
		if (n == 0) return false;
		if (errno == EINTR) continue;
		return errno == EAGAIN || errno == EWOULDBLOCK;
	}
}

} // namespace

RunResult run_process(
	const std::vector<std::string>& args, const RunOptions& opts) {
	if (args.empty()) throw std::invalid_argument("empty command");

	// Everything the child needs is prepared before fork().
	std::vector<char*> argv;
	for (const auto& a : args)
		argv.push_back(const_cast<char*>(a.c_str()));
	argv.push_back(nullptr);

	int out_pipe[2], err_pipe[2];
	if (pipe(out_pipe) != 0) throw std::runtime_error("pipe failed");
	if (pipe(err_pipe) != 0) {
		close(out_pipe[0]);
		close(out_pipe[1]);
		throw std::runtime_error("pipe failed");
	}

	pid_t pid = fork();
	if (pid < 0) {
		for (int fd : { out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1] })
			close(fd);
		throw std::runtime_error(
			std::string("fork failed: ") + std::strerror(errno));
	}
	if (pid == 0) {
		// Child: async-signal-safe calls only.
		setpgid(0, 0);
		int devnull = open("/dev/null", O_RDONLY);
		if (devnull >= 0) dup2(devnull, 0);
		dup2(out_pipe[1], 1);
		dup2(err_pipe[1], 2);
		for (int fd : { out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1] })
			close(fd);
		execvp(argv[0], argv.data());
		const char msg[] = "exec failed\n";
		ssize_t ignored = write(2, msg, sizeof msg - 1);
		(void)ignored;
		_exit(127);
	}

	setpgid(pid, pid); // also from the parent, avoiding a race with early kill
	close(out_pipe[1]);
	close(err_pipe[1]);
	set_nonblocking(out_pipe[0]);
	set_nonblocking(err_pipe[0]);

	RunResult res;
	const auto deadline = Clock::now() + opts.timeout;
	bool out_open = true, err_open = true;
	bool term_sent = false, kill_sent = false;
	Clock::time_point term_at;

	auto stop = [&] {
		if (!term_sent) {
			killpg(pid, SIGTERM);
			term_sent = true;
			term_at = Clock::now();
		}
	};

	while (out_open || err_open) {
		if (!term_sent) {
			if (opts.cancel && opts.cancel->load()) {
				res.cancelled = true;
				stop();
			} else if (Clock::now() >= deadline) {
				res.timed_out = true;
				stop();
			} else if (res.output_truncated) {
				stop();
			}
		} else if (!kill_sent && Clock::now() - term_at >= opts.kill_grace) {
			killpg(pid, SIGKILL);
			kill_sent = true;
		}

		pollfd fds[2];
		int n = 0;
		if (out_open) fds[n++] = { out_pipe[0], POLLIN, 0 };
		if (err_open) fds[n++] = { err_pipe[0], POLLIN, 0 };
		int rc = poll(fds, static_cast<nfds_t>(n), 100);
		if (rc < 0 && errno != EINTR) break;
		if (out_open)
			out_open = drain(
				out_pipe[0], res.out, opts.max_output, &res.output_truncated);
		if (err_open) err_open = drain(err_pipe[0], res.err, 1u << 20, nullptr);
	}
	close(out_pipe[0]);
	close(err_pipe[0]);

	int status = 0;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
	if (WIFEXITED(status)) res.exit_code = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		res.term_signal = WTERMSIG(status);
	killpg(pid, SIGKILL); // reap any stragglers left in the group
	return res;
}

} // namespace proculus
