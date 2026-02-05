#include <string_view>
#include <unistd.h>

#include "../include/helpers.h"
#include "../include/config_utils.h"

static inline bool parse_bool(std::string_view v, bool& out) {
    v = trim(v);
    if (ieq(v,"1")||ieq(v,"true")||ieq(v,"yes")||ieq(v,"on"))   { out=true;  return true; }
    if (ieq(v,"0")||ieq(v,"false")||ieq(v,"no") ||ieq(v,"off")) { out=false; return true; }
    return false;
}

static inline bool parse_int(std::string_view v, int& out) {
    v = trim(v);
    if (v.empty()) return false;

    int sign = 1;
    size_t i = 0;
    if (v[0]=='-') { 
        sign = -1;
        i = 1;
    }

    long acc = 0;
    for (; i < v.size(); ++i) {
        char c = v[i];
        if (c < '0' || c > '9') return false;
        acc = acc*10 + (c - '0');
        if (acc > 1'000'000'000L) break;
    }
    out = (int)(acc*sign);
    return true;
}

static inline bool is_safe_fd(int fd) {
    struct stat st{};
    if (fstat(fd, &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) return false;

    // deny group/world-writable
    if ((st.st_mode & 022) != 0) {
        fprintf(
            stderr, 
            "[ERROR] Refusing config (writable by group/other).\n"
        );
        return false;
    }

    // owner must be current user (or root)
    uid_t uid = getuid();
    if (!(st.st_uid == uid || st.st_uid == 0)) {
        fprintf(
            stderr, 
            "[ERROR] Refusing config (owner mismatch): expected uid: %d, got: %d\n", uid, st.st_uid
        );
        return false;
    }
    return true;
}

bool GlobalFilesendConfig::read(std::string& out) {
    int fd = ::open(cfg_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        perror("config open");
        return false;
    }

    if (!is_safe_fd(fd)) {
        ::close(fd);
        return false;
    }

    struct stat st{};
    if (fstat(fd, &st) != 0) {
        perror("config stat");
        ::close(fd); 
        return false;
    }

    out.clear();
    out.resize((size_t)st.st_size);
    size_t off = 0;
    while (off < (size_t)st.st_size) {
        ssize_t n = ::read(fd, out.data()+off, (size_t)st.st_size-off);

        if (n <= 0) { 
            ::close(fd);
            return false;
        
        }
        off += (size_t)n;
    }

    ::close(fd);
    return true;
}

void GlobalFilesendConfig::set(std::string_view section, std::string_view key, std::string_view val) {
    // GLOBAL
    if (section == "global") {
        if      (key == "device_id") cfg.device_id.assign(val.data(), val.size());
        else if (key == "cert_path") cfg.policy.cert_path.assign(val.data(), val.size());
        else if (key == "use_config")    { bool b; if (parse_bool(val,b)) cfg.use_config = b;    }
        else if (key == "security_info") { bool b; if (parse_bool(val,b)) cfg.security_info = b; }
        return;
    }

    // SEND
    if (section == "send") {
        if      (key == "use_ws")  { bool b; if (parse_bool(val,b)) cfg.use_ws = b ? true : false; }
        else if (key == "url")     { cfg.policy.url.assign(val.data(), val.size()); }
        else if (key == "timeout") { int s; if (parse_int(val,s)) cfg.policy.timeout = std::chrono::seconds(std::max(0,s)); }
        else if (key == "retry")   { 
            int n;
            if (parse_int(val,n)) {
                cfg.policy.retry_send.max_attempts = 
                cfg.policy.retry_connect.max_attempts = 
                std::max(1, std::abs(n)); 
            }
        }
#ifdef USE_MULTITHREADING
        else if (key == "nthreads") { int n; if (parse_int(val,n)) cfg.nthreads = std::max(1, n); }
#endif
        else if (key == "batch_size") { int n; if (parse_int(val,n)) cfg.batch_size = (std::size_t)std::max(1,n); }
        else if (key == "batch_format") cfg.batch_format.assign(val.data(), val.size());
        return;
    }

    // CRYPTO
    if (section == "crypto") {
        cfg.policy.enc_p.flags |= ENC_FLAG_ENABLED;

        if (key == "mode") {
            if (ieq(val, "symmetric")) cfg.policy.enc_p.flags |= ENC_FLAG_SYMMETRIC;
            else cfg.policy.enc_p.flags &= ~ENC_FLAG_SYMMETRIC;
        } else if (key == "all") {
            bool b; 
            if (parse_bool(val,b) && b) cfg.policy.enc_p.flags |= ENC_FLAG_ALL;
        } else if (key == "archive") {
            bool b; 
            if (parse_bool(val,b) && b) cfg.policy.enc_p.flags |= ENC_FLAG_ARCHIVE;
        } else if (key == "force") {
            bool b; 
            if (parse_bool(val,b) && b) cfg.policy.enc_p.flags |= ENC_FLAG_FORCE;
        } else if (key == "sym_key_path") {
            cfg.policy.enc_p.key_path.assign(val.data(), val.size());
            cfg.policy.enc_p.flags |= ENC_FLAG_SYMMETRIC;
        } else if (key == "pub_key_path") {
            cfg.policy.enc_p.key_path.assign(val.data(), val.size());
            cfg.policy.enc_p.flags &= ~ENC_FLAG_SYMMETRIC; // implies asymmetric
        } else if (key == "pr_key_path") {
            cfg.policy.enc_p.dec_key_path.assign(val.data(), val.size());
        } else if (key == "dest_path") {
            cfg.dest_path.assign(val.data(), val.size());
        }
        return;
    }
}

FilesendConfig GlobalFilesendConfig::load() {
    std::string buf;
    if (!this->read(buf)) return {};

    std::string_view section = "global";
    std::string_view s(buf);

    while (!s.empty()) {
        size_t eol = s.find('\n');
        std::string_view line = (eol == std::string_view::npos) ? s : s.substr(0, eol);
        s = (eol == std::string_view::npos) ? std::string_view{} : s.substr(eol + 1);

        line = trim(line);
        if (line.empty()) continue;
        if (line.front()=='#' || line.front()==';') continue;

        if (line.front()=='[' && line.back()==']') {
            section = trim(line.substr(1, line.size()-2));
            continue;
        }

        size_t eq = line.find('=');
        if (eq == std::string_view::npos) continue;

        std::string_view key = trim(line.substr(0, eq));
        std::string_view val = trim(line.substr(eq+1));
        if (key.empty()) continue;

        this->set(section, key, val);
    }

    return this->cfg;
}
