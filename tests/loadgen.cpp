/**
 * loadgen — high-throughput WebSocket load generator for the Socketlink server.
 *
 * The Python harness (loadtest.py) is GIL-bound around ~700k-1.8M deliveries/s
 * and was the measured bottleneck in every benchmark; this exists to find the
 * server's actual ceiling. Plaintext ws:// only (the server terminates TLS at
 * the load balancer), epoll, one thread per connection shard.
 *
 * Design choices for speed:
 *   - the publish frame is pre-masked ONCE per connection (identical payload
 *     every send), so the send path is a single send() syscall
 *   - the receive path is a streaming parser with O(1) per-connection state:
 *     it counts frames and discards payload bytes without buffering them
 *   - PING is answered with PONG (payload echoed) so idle timeouts never fire
 *
 * Build: make loadgen   (or: g++ -O2 -std=c++17 -pthread tests/loadgen.cpp -o build/loadgen)
 * Usage: loadgen --host 127.0.0.1 --port 8080 --conns 20000 --threads 16 \
 *               --group 10 --rate 5 --duration 15 --size 1024 [--prefix pub-grp-] [--flood]
 *   --rate 0 (or --flood) = send as fast as the socket accepts.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;

/* ------------------------------- config ---------------------------------- */
struct Config {
    std::string host = "127.0.0.1";
    int port = 8080;
    int conns = 10000;
    int threads = 16;
    int group = 10;
    double rate = 5.0; /* msgs/s per conn; 0 = flood */
    double duration = 15.0;
    int size = 1024; /* message body bytes */
    std::string prefix = "pub-grp-";
    std::string uidPrefix = "lg";
    /** --idle: connect and hold, never publish. Isolates connection capacity
     *  from message throughput (keepalive pings are still answered, so the
     *  server does not time the connections out). */
    bool idle = false;
    /** --no-subscribe: skip the REST room subscribe, leaving each connection
     *  subscribed only to the topics the server adds itself (its uid and the
     *  broadcast topic). */
    bool noSubscribe = false;
    std::string clientKey = "change-me-client-key";
    /** Source IPs to rotate over. One local IP affords only ~28k ephemeral ports
     *  toward a given destination, which caps a co-located client at ~28k
     *  connections regardless of server capacity; each extra 127.0.0.x adds
     *  another full range. Empty entry = let the OS choose. */
    std::vector<std::string> srcIps{""};
    double connectTimeout = 120.0;
};

/* ------------------------------ global stats ------------------------------ */
std::atomic<long long> g_sent{0}, g_recv{0}, g_recvBytes{0}, g_connected{0}, g_connectFailed{0};
std::atomic<bool> g_go{false}, g_stop{false};

/* ------------------------------ small helpers ----------------------------- */
/** Resolve a host (name or IPv4 literal) to dotted-quad, "" on failure. */
static std::string resolveHost(const std::string& host) {
    in_addr probe{};
    if (inet_pton(AF_INET, host.c_str(), &probe) == 1)
        return host;
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res)
        return "";
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &((sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf));
    freeaddrinfo(res);
    return buf;
}

static int dialBlocking(const std::string& host, int port, const std::string& srcIp = "") {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (!srcIp.empty()) {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = 0; /* any ephemeral port on THIS source address */
        inet_pton(AF_INET, srcIp.c_str(), &local.sin_addr);
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, (sockaddr*)&local, sizeof(local)) != 0) {
            close(fd);
            return -1;
        }
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

static bool sendAll(int fd, const char* p, size_t n) {
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && (errno == EAGAIN || errno == EINTR))
                continue;
            return false;
        }
        p += w;
        n -= (size_t)w;
    }
    return true;
}

/** Read until the buffer contains \r\n\r\n (HTTP head). Returns head or "" on error. */
static std::string readHttpHead(int fd) {
    std::string buf;
    char tmp[4096];
    while (buf.find("\r\n\r\n") == std::string::npos) {
        ssize_t r = recv(fd, tmp, sizeof(tmp), 0);
        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            return "";
        }
        buf.append(tmp, (size_t)r);
        if (buf.size() > 65536)
            return "";
    }
    return buf;
}

/** Build a masked client->server text frame around `payload`. */
static std::string buildFrame(const std::string& payload) {
    std::string f;
    size_t n = payload.size();
    f.push_back((char)0x81); /* FIN | text */
    if (n < 126) {
        f.push_back((char)(0x80 | n));
    } else if (n < 65536) {
        f.push_back((char)(0x80 | 126));
        f.push_back((char)((n >> 8) & 0xFF));
        f.push_back((char)(n & 0xFF));
    } else {
        f.push_back((char)(0x80 | 127));
        for (int i = 7; i >= 0; --i)
            f.push_back((char)((n >> (8 * i)) & 0xFF));
    }
    /* fixed mask: the server doesn't require unpredictability and this lets the
     * whole frame be precomputed once */
    unsigned char mask[4] = {0x12, 0x34, 0x56, 0x78};
    f.append((const char*)mask, 4);
    for (size_t i = 0; i < n; ++i)
        f.push_back((char)(payload[i] ^ mask[i % 4]));
    return f;
}

/* --------------------------- per-connection state ------------------------- */
struct Conn {
    int fd = -1;
    std::string frame;   /* pre-masked publish frame */
    size_t framePos = 0; /* partial-send resume point (flood mode) */
    bool writable = true;

    /* streaming receive parser: header accumulator + payload skip counter */
    unsigned char hdr[14];
    int hdrLen = 0;
    int hdrNeed = 2;
    long long payloadLeft = 0;
    int opcode = 0;
    std::string pingPayload; /* PING payload (<=125) echoed in the PONG */
};

/** Feed `n` bytes into the frame parser; counts data frames, answers pings. */
static void onBytes(Conn& c, const char* p, ssize_t n) {
    long long frames = 0, bytes = 0;
    while (n > 0) {
        if (c.payloadLeft > 0) { /* skipping payload */
            long long take = (n < c.payloadLeft) ? n : c.payloadLeft;
            if (c.opcode == 0x9 && c.pingPayload.size() < 125)
                c.pingPayload.append(p, (size_t)take);
            c.payloadLeft -= take;
            p += take;
            n -= take;
            if (c.payloadLeft == 0) {
                if (c.opcode == 0x1 || c.opcode == 0x2) {
                    ++frames;
                } else if (c.opcode == 0x9) {
                    std::string pong = std::string(1, (char)0x8A);
                    pong.push_back((char)(0x80 | c.pingPayload.size()));
                    unsigned char mask[4] = {0, 0, 0, 0};
                    pong.append((const char*)mask, 4);
                    pong += c.pingPayload; /* mask 0 => payload unchanged */
                    sendAll(c.fd, pong.data(), pong.size());
                    c.pingPayload.clear();
                }
                c.hdrLen = 0;
                c.hdrNeed = 2;
            }
            continue;
        }
        /* accumulating header */
        c.hdr[c.hdrLen++] = (unsigned char)*p;
        ++p;
        --n;
        if (c.hdrLen < c.hdrNeed)
            continue;
        if (c.hdrLen == 2) {
            int len = c.hdr[1] & 0x7F;
            int ext = (len == 126) ? 2 : (len == 127) ? 8 : 0;
            int maskBytes = (c.hdr[1] & 0x80) ? 4 : 0; /* server never masks */
            if (ext + maskBytes > 0) {
                c.hdrNeed = 2 + ext + maskBytes;
                if (c.hdrLen < c.hdrNeed)
                    continue;
            }
        }
        /* full header */
        {
            c.opcode = c.hdr[0] & 0x0F;
            int len = c.hdr[1] & 0x7F;
            long long plen = len;
            if (len == 126)
                plen = ((long long)c.hdr[2] << 8) | c.hdr[3];
            else if (len == 127) {
                plen = 0;
                for (int i = 0; i < 8; ++i)
                    plen = (plen << 8) | c.hdr[2 + i];
            }
            bytes += plen;
            if (plen == 0) {
                if (c.opcode == 0x1 || c.opcode == 0x2)
                    ++frames;
                else if (c.opcode == 0x9) {
                    static const char pong0[] = {(char)0x8A, (char)0x80, 0, 0, 0, 0};
                    sendAll(c.fd, pong0, sizeof(pong0));
                }
                c.hdrLen = 0;
                c.hdrNeed = 2;
            } else {
                c.payloadLeft = plen;
            }
        }
    }
    if (frames)
        g_recv.fetch_add(frames, std::memory_order_relaxed);
    if (bytes)
        g_recvBytes.fetch_add(bytes, std::memory_order_relaxed);
}

/* ------------------------------ worker thread ----------------------------- */
static void worker(const Config& cfg, int firstConn, int lastConn) {
    int count = lastConn - firstConn;
    std::vector<Conn> conns((size_t)count);
    std::vector<epoll_event> events(1024);
    char rbuf[65536];

    int ep = epoll_create1(0);

    /**
     * Service already-established sockets DURING the connect ramp. uWS sends
     * keepalive pings and closes anything idle past idleTimeout (120s by
     * default); a long ramp that never reads would let the server time out the
     * connections made at the start — the client would report tens of thousands
     * "connected" while the server had already closed most of them.
     */
    auto pump = [&]() {
        int nev = epoll_wait(ep, events.data(), (int)events.size(), 0);
        for (int e = 0; e < nev; ++e) {
            Conn& c = *(Conn*)events[e].data.ptr;
            if (c.fd < 0)
                continue;
            ssize_t r;
            while ((r = recv(c.fd, rbuf, sizeof(rbuf), 0)) > 0)
                onBytes(c, rbuf, r);
            if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR)) {
                epoll_ctl(ep, EPOLL_CTL_DEL, c.fd, nullptr);
                close(c.fd);
                c.fd = -1;
                g_connected.fetch_sub(1);
            }
        }
    };

    /* one keep-alive HTTP connection for all REST subscribes in this shard */
    int http = dialBlocking(cfg.host, cfg.port, cfg.srcIps[0]);

    for (int k = 0; k < count; ++k) {
        int i = firstConn + k;
        std::string uid = cfg.uidPrefix + std::to_string(i);
        std::string rid = cfg.prefix + std::to_string(i / cfg.group);

        int fd = dialBlocking(cfg.host, cfg.port, cfg.srcIps[(size_t)i % cfg.srcIps.size()]);
        if (fd < 0) {
            g_connectFailed.fetch_add(1);
            continue;
        }
        std::string req = "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          "Sec-WebSocket-Key: bG9hZGdlbi1rZXktMTIzNDU=\r\nSec-WebSocket-Version: 13\r\n"
                          "api-key: " +
                          cfg.clientKey + "\r\nuid: " + uid + "\r\n\r\n";
        if (!sendAll(fd, req.data(), req.size()) || readHttpHead(fd).find(" 101 ") == std::string::npos) {
            close(fd);
            g_connectFailed.fetch_add(1);
            continue;
        }

        /* REST subscribe (keep-alive; response drained via Content-Length in head read) */
        if (http >= 0 && !cfg.noSubscribe) {
            std::string sreq = "GET /api/v1/users/subscribe/room/" + rid +
                               " HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\napi-key: " + cfg.clientKey +
                               "\r\nuid: " + uid + "\r\n\r\n";
            sendAll(http, sreq.data(), sreq.size());
            std::string head = readHttpHead(http);
            size_t hp = head.find("\r\n\r\n");
            long long cl = 0;
            /* crude content-length scan + drain of body bytes not already read */
            for (size_t pos = 0; (pos = head.find("ontent-", pos)) != std::string::npos; ++pos) {
                if (head.compare(pos - 1, 15, "Content-Length:") == 0 ||
                    head.compare(pos - 1, 15, "content-length:") == 0) {
                    cl = atoll(head.c_str() + pos + 14);
                    break;
                }
            }
            long long have = (long long)(head.size() - (hp + 4));
            while (have < cl) {
                char tmp[4096];
                ssize_t r = recv(http, tmp, sizeof(tmp), 0);
                if (r <= 0)
                    break;
                have += r;
            }
        }

        Conn& c = conns[(size_t)k];
        c.fd = fd;
        c.frame = buildFrame("{\"rid\":\"" + rid + "\",\"message\":\"" + std::string((size_t)cfg.size, 'x') + "\"}");

        /* non-blocking + epoll immediately, so pump() can service it while the
         * rest of this shard is still connecting */
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.ptr = &c;
        epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);

        g_connected.fetch_add(1);
        if ((k & 31) == 0)
            pump();
    }
    if (http >= 0)
        close(http);

    while (!g_go.load(std::memory_order_acquire)) {
        pump(); /* keep answering pings while other shards finish connecting */
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    /* --idle: hold the connections open and answer pings, never publish */
    if (cfg.idle) {
        while (!g_stop.load(std::memory_order_acquire)) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        for (auto& c : conns)
            if (c.fd >= 0)
                close(c.fd);
        close(ep);
        return;
    }

    const bool flood = cfg.rate <= 0.0;
    /* rate mode: this shard sends (rate * liveConns) msgs/s, round-robin */
    double shardRate = cfg.rate * (double)count;
    double tokens = 0;
    auto last = Clock::now();
    size_t rr = 0;

    while (!g_stop.load(std::memory_order_acquire)) {
        int nev = epoll_wait(ep, events.data(), (int)events.size(), flood ? 0 : 1);
        for (int e = 0; e < nev; ++e) {
            Conn& c = *(Conn*)events[e].data.ptr;
            if (events[e].events & (EPOLLERR | EPOLLHUP)) {
                epoll_ctl(ep, EPOLL_CTL_DEL, c.fd, nullptr);
                close(c.fd);
                c.fd = -1;
                continue;
            }
            if (events[e].events & EPOLLIN) {
                ssize_t r;
                while ((r = recv(c.fd, rbuf, sizeof(rbuf), 0)) > 0)
                    onBytes(c, rbuf, r);
                if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR)) {
                    epoll_ctl(ep, EPOLL_CTL_DEL, c.fd, nullptr);
                    close(c.fd);
                    c.fd = -1;
                    continue;
                }
            }
            if (events[e].events & EPOLLOUT) {
                c.writable = true;
                epoll_event ev{};
                ev.events = EPOLLIN;
                ev.data.ptr = &c;
                epoll_ctl(ep, EPOLL_CTL_MOD, c.fd, &ev);
            }
        }

        auto trySend = [&](Conn& c) -> bool {
            if (c.fd < 0 || !c.writable)
                return false;
            while (c.framePos < c.frame.size()) {
                ssize_t w = send(c.fd, c.frame.data() + c.framePos, c.frame.size() - c.framePos, MSG_NOSIGNAL);
                if (w > 0) {
                    c.framePos += (size_t)w;
                    continue;
                }
                if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    c.writable = false; /* resume via EPOLLOUT */
                    epoll_event ev{};
                    ev.events = EPOLLIN | EPOLLOUT;
                    ev.data.ptr = &c;
                    epoll_ctl(ep, EPOLL_CTL_MOD, c.fd, &ev);
                    return false;
                }
                if (w < 0 && errno == EINTR)
                    continue;
                epoll_ctl(ep, EPOLL_CTL_DEL, c.fd, nullptr);
                close(c.fd);
                c.fd = -1;
                return false;
            }
            c.framePos = 0;
            g_sent.fetch_add(1, std::memory_order_relaxed);
            return true;
        };

        if (flood) {
            for (auto& c : conns)
                trySend(c);
        } else {
            auto now = Clock::now();
            tokens += shardRate * std::chrono::duration<double>(now - last).count();
            last = now;
            if (tokens > shardRate) /* cap the backlog to ~1s of sends */
                tokens = shardRate;
            int budget = (int)tokens;
            tokens -= budget;
            while (budget > 0 && !conns.empty()) {
                Conn& c = conns[rr++ % conns.size()];
                if (c.fd >= 0)
                    trySend(c);
                --budget;
            }
        }
    }

    for (auto& c : conns)
        if (c.fd >= 0)
            close(c.fd);
    close(ep);
}

/* ---------------------------------- main ---------------------------------- */
int main(int argc, char** argv) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> const char* { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--host")
            cfg.host = next();
        else if (a == "--port")
            cfg.port = atoi(next());
        else if (a == "--conns")
            cfg.conns = atoi(next());
        else if (a == "--threads")
            cfg.threads = atoi(next());
        else if (a == "--group")
            cfg.group = atoi(next());
        else if (a == "--rate")
            cfg.rate = atof(next());
        else if (a == "--flood")
            cfg.rate = 0;
        else if (a == "--duration")
            cfg.duration = atof(next());
        else if (a == "--size")
            cfg.size = atoi(next());
        else if (a == "--prefix")
            cfg.prefix = next();
        else if (a == "--idle")
            cfg.idle = true;
        else if (a == "--no-subscribe")
            cfg.noSubscribe = true;
        else if (a == "--uid-prefix")
            cfg.uidPrefix = next();
        else if (a == "--key")
            cfg.clientKey = next();
        else if (a == "--connect-timeout")
            cfg.connectTimeout = atof(next());
        else if (a == "--src-ips") {
            cfg.srcIps.clear();
            std::string list = next(), cur;
            for (char ch : list) {
                if (ch == ',') {
                    cfg.srcIps.push_back(cur);
                    cur.clear();
                } else
                    cur.push_back(ch);
            }
            cfg.srcIps.push_back(cur);
            if (cfg.srcIps.empty())
                cfg.srcIps.push_back("");
        }
        else {
            fprintf(stderr, "unknown arg: %s\n", a.c_str());
            return 2;
        }
    }

    rlimit rl{};
    getrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rl);

    /** resolve once: workers dial by IP (container DNS names must work too) */
    std::string resolved = resolveHost(cfg.host);
    if (resolved.empty()) {
        fprintf(stderr, "[loadgen] cannot resolve host '%s'\n", cfg.host.c_str());
        return 2;
    }
    cfg.host = resolved;

    fprintf(stderr, "[loadgen] connecting %d conns across %d threads (group=%d, rate=%.1f, size=%d)...\n", cfg.conns,
            cfg.threads, cfg.group, cfg.rate, cfg.size);

    std::vector<std::thread> threads;
    int per = cfg.conns / cfg.threads;
    for (int t = 0; t < cfg.threads; ++t) {
        int a = t * per;
        int b = (t == cfg.threads - 1) ? cfg.conns : a + per;
        threads.emplace_back(worker, std::cref(cfg), a, b);
    }

    auto t0 = Clock::now();
    while (g_connected.load() + g_connectFailed.load() < cfg.conns) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (std::chrono::duration<double>(Clock::now() - t0).count() > cfg.connectTimeout)
            break;
    }
    double setup = std::chrono::duration<double>(Clock::now() - t0).count();
    fprintf(stderr, "[loadgen] connected %lld/%d in %.1fs (%lld failed)\n", (long long)g_connected.load(), cfg.conns,
            setup, (long long)g_connectFailed.load());

    /* measurement window */
    g_sent = 0;
    g_recv = 0;
    g_recvBytes = 0;
    g_go.store(true, std::memory_order_release);
    std::this_thread::sleep_for(std::chrono::duration<double>(cfg.duration));
    long long sent = g_sent.load(), recvd = g_recv.load(), rbytes = g_recvBytes.load();
    g_stop.store(true, std::memory_order_release);
    for (auto& t : threads)
        t.join();

    printf("{\n"
           "  \"connected\": %lld, \"connect_failed\": %lld, \"setup_s\": %.1f,\n"
           "  \"group\": %d, \"rate\": %.1f, \"size\": %d, \"window_s\": %.1f,\n"
           "  \"sent\": %lld, \"recv\": %lld,\n"
           "  \"send_rate_msgs_s\": %.0f, \"recv_rate_msgs_s\": %.0f, \"recv_MB_s\": %.1f\n"
           "}\n",
           (long long)g_connected.load(), (long long)g_connectFailed.load(), setup, cfg.group, cfg.rate, cfg.size,
           cfg.duration, sent, recvd, (double)sent / cfg.duration, (double)recvd / cfg.duration,
           (double)rbytes / cfg.duration / 1e6);
    return 0;
}
