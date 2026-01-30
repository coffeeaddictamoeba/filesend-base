#include <cstdio>
#include <filesystem>

#include "../include/arg_utils.h"

namespace fs = std::filesystem; // maybe will be removed because of cf.init_path being a pattern

ArgParser::ArgParser() {
    config_ = {};
    mode_handlers_ = {
        // General
        {"--help", [this](int argc, char** argv) { (void)argc, usage(argv[0]); }},

        // Modes
        {"send",    [this](int argc, char** argv) { handle_send(argc, argv); }},
        {"encrypt", [this](int argc, char** argv) { handle_security_settings(argc, argv); }},
        {"decrypt", [this](int argc, char** argv) { handle_security_settings(argc, argv); }},
        {"verify",  [this](int argc, char** argv) { handle_verify(argc, argv); }},
    };
}

void ArgParser::usage(const char* prog) const {
    fprintf(
        stderr,
        "Usage:\n"
        "  %s send  [--https|--ws]  <path> <url> "
        "[--encrypt symmetric|asymmetric] [--all] "
        "[--timeout <n>] [--retry <n>] [--no-retry] "
        "[--batch <n> <format>] [--archive] [--nthreads <n>]\n" 

        "  %s encrypt <path> [--symmetric|--asymmetric] [--all] "
        "[--dest <file>] [--timeout <n>]\n"

        "  %s decrypt <path> [--symmetric|--asymmetric] [--all] "
        "[--dest <file>] [--timeout <n>]\n"
        
        "  %s verify <path> <sha256>\n",
        prog, prog, prog, prog
    );
}

void ArgParser::init_config() {
    config_ = {};  // reset config

    config_.device_id = getenv_or_default(
        DEVICE_ID_ENV, 
        DEFAULT_DEVICE_ID
    );
    config_.batch_size = 1;

    config_.policy.timeout = std::chrono::seconds(0);
    config_.policy.enc_p.dec_key_path = getenv_or_default(
        PR_KEY_ENV, 
        DEFAULT_PR_KEY_PATH
    );

    config_.policy.cert_path = getenv_or_default(
        CERT_PATH_ENV, 
        DEFAULT_CA_CERT_PATH
    );

    config_.policy.enc_p.key_path = "";
}

int ArgParser::parse(int argc, char** argv) {
    if (argc < 3) {
        usage(argv[0]);
        return -1;
    }

    init_config();

    config_.mode = argv[1];     
    if (mode_handlers_.find(config_.mode) != mode_handlers_.end()) {
        mode_handlers_[config_.mode](argc, argv);
    } else {
        fprintf(
            stderr, 
            "[ERROR] Unknown mode: %s\n", config_.mode.c_str()
        );
        usage(argv[0]);
        return -1;
    }

    return 0;
}

void ArgParser::handle_send_encrypt(int& value, int argc, char** argv) {
    if (value + 1 >= argc) {
        fprintf(
            stderr,
            RED "[ERROR] --encrypt requires 'symmetric' or 'asymmetric'\n" RESET
        );
        return;
    }

    config_.policy.enc_p.flags |= ENC_FLAG_ENABLED;

    const char* mode = argv[++value];

    if (strcmp(mode, "symmetric") == 0) {
        config_.policy.enc_p.flags   |= ENC_FLAG_SYMMETRIC;
        config_.policy.enc_p.key_path = getenv_or_default(
            SYM_KEY_ENV, 
            DEFAULT_SYM_KEY_PATH
        );
    } else if (strcmp(mode, "asymmetric") == 0) {
        config_.policy.enc_p.key_path = getenv_or_default(
            PUB_KEY_ENV, 
            DEFAULT_PUB_KEY_PATH
        );
    } else {
        fprintf(
            stderr,
            RED "[ERROR] Only symmetric and asymmetric key modes are possible\n" RESET
        );
        return;
    }
}

void ArgParser::handle_send_batch(int& value, int argc, char** argv) {
    if (value + 1 >= argc) {
        std::fprintf(
            stderr,
            RED "[ERROR] --batch requires integer size and compression format\n" RESET
        );
        return;
    }

    config_.batch_size = std::max((int)config_.batch_size, std::atoi(argv[++value]));

    if (value + 1 < argc) {
        for (const auto& format : COMPRESSION_FORMATS_AVAILABLE) {
            if (strcmp(format, argv[value+1]) == 0) {
                config_.batch_format = argv[++value];
                break;
            }
        }
    }

    if (config_.batch_format.empty()) config_.batch_format = DEFAULT_COMPRESSION_FORMAT;
}

void ArgParser::handle_mode_timeout(int& value, int argc, char** argv) {
    if (value + 1 >= argc) {
        fprintf(
            stderr,
            RED "[ERROR] --timeout requires integer seconds\n" RESET
        );
        return;
    }

    config_.policy.timeout = std::max(
        config_.policy.timeout, 
        std::chrono::seconds(std::atoi(argv[++value]))
    );
}

void ArgParser::handle_mode_threads(int& value, int argc, char** argv) {
#ifdef USE_MULTITHREADING
    if (value + 1 >= argc) {
        fprintf(
            stderr,
            RED "[ERROR] --nthreads requires positive integer threads number\n" RESET
        );
        return;
    }

    config_.nthreads = std::atoi(argv[++value]);
#else
    fprintf(
        stderr, 
        YELLOW "[WARN] Program was compiled without support for multithreading. "
        "To enable it, compile with \"-DUSE_MULTITHREADING\"\n" RESET
    );

    if (value + 1 < argc) (void)argv[++value]; // consume the next argument
#endif
}

void ArgParser::handle_send_retry(int& value, int argc, char** argv) {
    if (value + 1 >= argc) {
        fprintf(
            stderr,
            RED "[ERROR] --retry requires integer count\n" RESET
        );
        return;
    }

    // make separate options later
    config_.policy.retry_send.max_attempts 
    = config_.policy.retry_connect.max_attempts 
    = std::abs(std::atoi(argv[++value]));
}

void ArgParser::handle_send(int argc, char** argv) {
    if (argc < 5 || (strcmp(argv[2], "--https") != 0 && strcmp(argv[2], "--ws") != 0)) {
        fprintf(
            stderr, 
            "[ERROR] send mode requires [--https|--ws] <path> <url>\n"
        );
        usage(argv[0]);
        return;
    }

    config_.use_ws = (strcmp(argv[2], "--ws") == 0);

    config_.init_path = argv[3]; // Path
    if (!fs::exists(config_.init_path)) {
        fprintf(
            stderr, 
            RED "[ERROR] There is no path with name \"%s\" \r\n" RESET, config_.init_path.c_str()
        );
        return;
    }

    config_.policy.url = argv[4]; // URL

    for (int i = 5; i < argc; ++i) {
        const char* arg = argv[i];
        if      (strcmp(arg, "--encrypt") == 0)  { handle_send_encrypt(i, argc, argv); } 
        else if (strcmp(arg, "--all") == 0)      { config_.policy.enc_p.flags |= ENC_FLAG_ALL; } 
        else if (strcmp(arg, "--archive") == 0)  { config_.policy.enc_p.flags |= ENC_FLAG_ARCHIVE; } 
        else if (strcmp(arg, "--batch") == 0)    { handle_send_batch(i, argc, argv); }
        else if (strcmp(arg, "--timeout") == 0)  { handle_mode_timeout(i, argc, argv); }
        else if (strcmp(arg, "--retry") == 0)    { handle_send_retry(i, argc, argv); }
        else if (strcmp(arg, "--no-retry") == 0) { config_.policy.retry_send.max_attempts = config_.policy.retry_connect.max_attempts = 1; } // separate?
        else if (strcmp(arg, "--nthreads") == 0) { handle_mode_threads(i, argc, argv); }
        else {
            fprintf(
                stderr,
                RED "[ERROR] Unknown argument in send mode: %s\n" RESET, arg
            );
            return;
        }
    }

// #ifdef USE_MULTITHREADING
//     if (config_.nthreads > 1 || config_.nthreads <= 0) config_.batch_size = 1; // safety measure for now, will be fixed later
// #endif
}

void ArgParser::handle_key_mode(const char* flag, const char* mode) {
    if (strcmp(flag, "--symmetric") == 0) {
        config_.policy.enc_p.flags   |= ENC_FLAG_SYMMETRIC;
        config_.policy.enc_p.key_path = getenv_or_default(
            SYM_KEY_ENV, 
            DEFAULT_SYM_KEY_PATH
        );
    } else if (strcmp(flag, "--asymmetric") == 0) {
        config_.policy.enc_p.key_path = getenv_or_default(
            PUB_KEY_ENV, 
            DEFAULT_PUB_KEY_PATH
        );
    } else {
        fprintf(
            stderr, 
            RED "[ERROR] There is no key mode \"%s\" for %s\n" RESET, flag, mode
        );
    }
}

void ArgParser::handle_mode_dest(int& value, int argc, char** argv) {
    if (value + 1 >= argc) {
        fprintf(
            stderr,
            RED "[ERROR] --dest requires a file/directory path\n" RESET
        );
        return;
    }
    config_.dest_path = argv[++value];
}

void ArgParser::handle_security_settings(int argc, char** argv) {
    if (argc < 4) {
        fprintf(
            stderr, 
            "[ERROR] encrypt/decrypt modes require <path> [--symmetric|--asymmetric]\n"
        );
        usage(argv[0]);
        return;
    }

    config_.init_path = argv[2];

    config_.policy.enc_p.flags |= ENC_FLAG_ENABLED;

    handle_key_mode(argv[3], config_.mode.c_str());

    for (int i = 4; i < argc; ++i) {
        const char* arg = argv[i];    

        if (strcmp(arg, "--all") == 0)          { config_.policy.enc_p.flags |= ENC_FLAG_ALL; }
        else if (strcmp(arg, "--dest") == 0)    { handle_mode_dest(i, argc, argv); }
        else if (strcmp(arg, "--timeout") == 0) { handle_mode_timeout(i, argc, argv); }
        else {
            fprintf(
                stderr, 
                RED "[ERROR] Unknown argument in encrypt/decrypt mode: %s\n", arg
            );
            return;
        }
    }

    if (config_.dest_path.empty()) config_.dest_path = config_.init_path;
}

void ArgParser::handle_verify(int argc, char** argv) {
    (void)argc;
    config_.init_path = argv[2];
}