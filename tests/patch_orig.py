#!/usr/bin/env python3
"""Apply the LOCAL_TEST bypass (unconditionally) to the master/original source
so it can run on a dev box, matching the harness the optimized build uses."""
import sys, re

src = "/tmp/orig_master.cpp"
dst = "/tmp/orig_test.cpp"

with open(src, "r", encoding="utf-8") as f:
    code = f.read()

def repl(old, new, count_expected):
    global code
    n = code.count(old)
    if n != count_expected:
        print(f"FAIL: expected {count_expected} of:\n{old[:80]!r}\n but found {n}")
        sys.exit(1)
    code = code.replace(old, new)

# 1) main() provisioning block -> hardcoded config + init_env
old_main = '''    /** Fetch and populated data before starting the threads */
    fetchAndPopulateUserData();
    init_env();

    /** Keep retrying if subdomain is empty */
    while (UserData::getInstance().subdomain.empty()) {
        log(LogLevel::INFO, "Subdomain is empty, retrying fetch in 10 seconds...\\n");
        std::this_thread::sleep_for(std::chrono::seconds(10));
        fetchAndPopulateUserData();
    }

    log(LogLevel::INFO, "Successfully fetched user data!");'''

new_main = '''    /** LOCAL_TEST bypass applied to original source for benchmarking */
    {
        auto& u = UserData::getInstance();
        u.clientApiKey = "test-client-key";
        u.adminApiKey  = "test-admin-key";
        u.connections  = 1000000;
        u.maxMonthlyPayloadInBytes = 1ULL << 50;
        u.lmdbDatabaseSizeInBytes  = 1ULL << 30;
        u.msgSizeAllowedInBytes    = 1 << 20;
        u.maxBackpressureInBytes   = 1 << 20;
        u.idleTimeoutInSeconds     = 120;
        u.subdomain = "localtest";
        if (std::getenv("SL_TEST_WEBHOOK")) {
            u.webHookBaseUrl = "127.0.0.1";
            u.webhookPath    = "/webhook";
            u.webhookIP      = "127.0.0.1";
            populateWebhookStatus(static_cast<uint8_t>(Webhooks::ON_MESSAGE));
            log(LogLevel::INFO, "LOCAL_TEST (orig): ON_MESSAGE webhook enabled -> 127.0.0.1:8443");
        }
    }
    init_env();
    log(LogLevel::INFO, "LOCAL_TEST mode (original): cloud provisioning bypassed.");'''

repl(old_main, new_main, 1)

# 2) Remove the DNS/cert/watcher block (whitespace-tolerant).
dns_pat = re.compile(
    r'[ \t]*std::string domain = UserData::getInstance\(\)\.subdomain.*?watcher\.detach\(\);[ \t]*\n',
    re.DOTALL,
)
new_code, n = dns_pat.subn("", code)
if n != 1:
    print(f"FAIL: DNS block matched {n} times")
    sys.exit(1)
code = new_code

# 3) cert/key paths
old_cert = '''    const std::string keyFilePath = "/home/socketlink/certbot-config/live/" + UserData::getInstance().subdomain + ".socketlink.io/privkey.pem";
    const std::string certFileName = "/home/socketlink/certbot-config/live/" + UserData::getInstance().subdomain + ".socketlink.io/fullchain.pem";'''
new_cert = '''    const std::string keyFilePath = "./ssl/privkey.pem";
    const std::string certFileName = "./ssl/cert.pem";'''
repl(old_cert, new_cert, 1)

# 3b) webhook endpoint port 443 -> 8443 (local mock)
old_wh = '''                boost::asio::ip::tcp::endpoint endpoint(
                    boost::asio::ip::make_address(UserData::getInstance().webhookIP),
                    443
                );'''
new_wh = '''                boost::asio::ip::tcp::endpoint endpoint(
                    boost::asio::ip::make_address(UserData::getInstance().webhookIP),
                    8443
                );'''
repl(old_wh, new_wh, 1)

# 4) listen port
repl(".listen(PORT,", ".listen(9001,", 1)
repl('listening on port ", PORT', 'listening on port ", 9001', 1)
repl('failed to listen on port ", PORT', 'failed to listen on port ", 9001', 1)

with open(dst, "w", encoding="utf-8") as f:
    f.write(code)

print("OK -> " + dst)
