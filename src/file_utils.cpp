#include <cstddef>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <utime.h>
#include <errno.h>

#include <sodium.h>
#include <sodium/crypto_hash_sha256.h>

#include "../include/file_utils.h"

int make_readonly(const char *path) {
    if (chmod(path, 0400) != 0) {
        perror("[WARN] chmod read-only failed");
        return -1;
    }
    return 0;
}

int match_pattern(const char* p, const char* t) {
    size_t p_idx     = 0;
    size_t t_idx     = 0;
    size_t match_pos = 0; // position in text when last '*' was seen
    size_t star_pos  = 0; // last position of '*' in pattern

    size_t p_len = strlen(p);
    size_t t_len = strlen(t);

    while (t_idx < t_len) {
        if (p_idx < p_len && p[p_idx] == '*') {
            star_pos = p_idx++;
            match_pos = t_idx;
        }

        else if (p_idx < p_len && (p[p_idx] == '?' || p[p_idx] == t[t_idx])) {
            ++p_idx;
            ++t_idx;
        }

        else if (star_pos != std::string::npos) {
            p_idx = star_pos + 1;
            ++match_pos;
            t_idx = match_pos;
        }

        else return 0;
    }

    while (p_idx < p_len && p[p_idx] == '*') ++p_idx;

    return p_idx == p_len;
}

int get_file_metadata(const char* path, file_metadata_t* fmd) {
    struct stat st;
    if (stat(path, &st) != 0) {
        perror(RED "stat" RESET);
        return -1;
    }

    fmd->size  = (uint64_t)st.st_size;
    fmd->mtime = (uint64_t)st.st_mtime;
    fmd->pmode = (uint32_t)st.st_mode;

    return 0;
}

int _sha256_file(const char *path, unsigned char digest[crypto_hash_sha256_BYTES]) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("[ERROR] fopen (sha256_file_internal)");
        return -1;
    }

    crypto_hash_sha256_state st;
    if (crypto_hash_sha256_init(&st) != 0) {
        fprintf(stderr, "[ERROR] crypto_hash_sha256_init failed\n");
        fclose(f);
        return -1;
    }

    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (crypto_hash_sha256_update(&st, buf, (unsigned long long)n) != 0) {
            fprintf(stderr, "[ERROR] crypto_hash_sha256_update failed\n");
            fclose(f);
            return -1;
        }
    }

    if (ferror(f)) {
        perror("[ERROR] fread (sha256_file_internal)");
        fclose(f);
        return -1;
    }

    if (crypto_hash_sha256_final(&st, digest) != 0) {
        fprintf(stderr, "[ERROR] crypto_hash_sha256_final failed\n");
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

/* raw 32-byte SHA-256. */
int compute_file_sha256(const char *path, unsigned char out[crypto_hash_sha256_BYTES]) {
    return _sha256_file(path, out);
}

/* hex string (65 bytes incl. '\0' if you want full SHA-256). */
int compute_file_sha256_hex(const char *path, char *hex_out, size_t hex_out_len) {
    unsigned char digest[crypto_hash_sha256_BYTES];

    if (hex_out_len < crypto_hash_sha256_BYTES * 2 + 1) {
        fprintf(
            stderr,
            RED "[ERROR] compute_file_sha256_hex: buffer too small (need at least %zu bytes)\n" RESET, (size_t)crypto_hash_sha256_BYTES * 2 + 1
        );
        return -1;
    }

    if (_sha256_file(path, digest) != 0) return -1;

    sodium_bin2hex(hex_out, hex_out_len, digest, crypto_hash_sha256_BYTES);
    return 0;
}

int verify_file_checksum(const char* file_path, const char* sha_received, size_t sha_len) {
    size_t len = 0;
    if (sha_len == crypto_hash_sha256_BYTES*2) {
        len = crypto_hash_sha256_BYTES*2+1;
        char sha_expected[len];
        if (compute_file_sha256_hex(file_path, sha_expected, sizeof(sha_expected)) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to compute hex checksum of %s\n" RESET, file_path 
            );
            return -1;
        }

        if (sodium_memcmp(sha_received, sha_expected, len) == 0) {
            fprintf(
                stdout,
                GREEN "[SUCCESS] Checksum match: %s\n" RESET, file_path 
            );
            return 0;
        }

        fprintf(
            stderr,
            RED "[ERROR] Checksum does not match: %s\n\t received: %s\n\t expected: %s\n" RESET, 
            file_path, sha_received, sha_expected
        );

    } else if (sha_len == crypto_hash_sha256_BYTES) {
        len = crypto_hash_sha256_BYTES;
        unsigned char sha_expected[len];
        if (compute_file_sha256(file_path, sha_expected) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to compute raw checksum of %s\n" RESET, file_path 
            );
            return -1;
        }

        if (sodium_memcmp(sha_received, sha_expected, len) == 0) {
            fprintf(
                stdout,
                GREEN "[SUCCESS] Checksum match: %s\n" RESET, file_path 
            );
            return 0;
        }
        
        fprintf(
            stderr,
            RED "[ERROR] Checksum does not match: %s\n\treceived: %s\n\texpected: %s\n" RESET, 
            file_path, sha_received, sha_expected
        );

    } else {
        fprintf(
            stderr,
            RED "[ERROR] Checksum length (%s): received: %zu, expected: %zu\n" RESET, file_path, sha_len, len
        );
        return -1;
    }
    
    return -1; // checksum mismatch
}

int encrypt_file_symmetric(const unsigned char* key, const char* plain_path, const char* enc_path, int enc_all) {
    FILE* fin = fopen(plain_path, "rb");
    if (!fin) {
        perror(RED "fopen plain_path in file encrypt" RESET);
        return -1;
    }

    char tmp_enc_path[1024];
    snprintf(tmp_enc_path, sizeof(tmp_enc_path), "%s.tmp", enc_path);

    FILE* fout = fopen(tmp_enc_path, "wb");
    if (!fout) {
        perror(RED "fopen enc_path in file encrypt" RESET);
        fclose(fin);
        return -1;
    }

    file_metadata_t md = {};
    int have_md = 0;
    if (get_file_metadata(plain_path, &md) == 0) {
        have_md = 1;
    } else {
        fprintf(
            stderr,
            RED "[WARN] Failed to get file metadata, continuing without\n" RESET
        );
    }

    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (crypto_secretstream_xchacha20poly1305_init_push(&st, header, key) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] crypto_secretstream_xchacha20poly1305_init_push failed\n" RESET
        );
        fclose(fin);
        fclose(fout);
        return -1;
    }

    if (fwrite(header, 1, sizeof(header), fout) != sizeof(header)) {
        fprintf(
            stderr,
            RED "[ERROR] Failed to write header\n" RESET
        );
        fclose(fin);
        fclose(fout);
        return -1;
    }

    unsigned long long out_len;
    // Optionally encrypt metadata as first chunk
    if (enc_all && have_md) {
        unsigned char meta_ct[sizeof(file_metadata_t) + crypto_secretstream_xchacha20poly1305_ABYTES];

        if (crypto_secretstream_xchacha20poly1305_push(&st, meta_ct, &out_len, (unsigned char*)&md, sizeof(md), NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] secretstream_push(meta) failed\n" RESET
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (fwrite(meta_ct, 1, out_len, fout) != out_len) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to write encrypted metadata\n" RESET
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }
    }

    unsigned char inbuf[CHUNK_SIZE];
    unsigned char outbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t n;
    int is_last;

    for (;;) {
        n = fread(inbuf, 1, CHUNK_SIZE, fin);
        if (ferror(fin)) {
            perror(RED "fread" RESET);
            fclose(fin);
            fclose(fout);
            return -1;
        }

        is_last = feof(fin);

        unsigned char tag = is_last
            ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
            : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        if (crypto_secretstream_xchacha20poly1305_push(&st, outbuf, &out_len, inbuf, n, NULL, 0, tag) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] secretstream_push failed\n" RESET
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (fwrite(outbuf, 1, out_len, fout) != out_len) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to write encrypted chunk\n" RESET
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (is_last) break;
    }

    fclose(fin);
    fclose(fout);

    if (rename(tmp_enc_path, enc_path) != 0) {
        perror(RED "rename" RESET);
        return -1;
    }

    if (enc_all && have_md) {
        printf(GREEN "[SUCCESS] File %s and its metadata were successfully encrypted (symmetric)\n" RESET, enc_path);
    } else {
        printf(GREEN "[SUCCESS] File %s was successfully encrypted (symmetric, content only)\n" RESET, enc_path);
    }

    return 0;
}

int decrypt_file_symmetric(const unsigned char* key, const char* enc_path, const char* dec_path, int dec_all) {
    FILE* fin = fopen(enc_path, "rb");
    if (!fin) {
        perror(RED "fopen of enc_path in decrypt file" RESET);
        return -1;
    }

    char tmp_dec_path[1024];
    snprintf(tmp_dec_path, sizeof(tmp_dec_path), "%s.tmp", dec_path);

    FILE* fout = fopen(tmp_dec_path, "wb");
    if (!fout) {
        perror(RED "fopen of dec_path in decrypt file" RESET);
        fclose(fin);
        return -1;
    }

    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (fread(header, 1, sizeof(header), fin) !=
        crypto_secretstream_xchacha20poly1305_HEADERBYTES)
    {
        if (feof(fin)) {
            fprintf(
                stderr,
                RED "[ERROR] Encrypted file is too short\n" RESET
            );
        } else {
            perror(RED "fread of header in decrypt file" RESET);
        }
        fclose(fin);
        fclose(fout);
        return -1;
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] crypto_secretstream_xchacha20poly1305_init_pull failed\n" RESET
        );
        fclose(fin);
        fclose(fout);
        return -1;
    }

    file_metadata_t md = {};
    int have_md = 0;

    if (dec_all) {
        size_t meta_ct_len = sizeof(file_metadata_t) + crypto_secretstream_xchacha20poly1305_ABYTES;
        unsigned char inbuf_meta[sizeof(file_metadata_t) + crypto_secretstream_xchacha20poly1305_ABYTES];
        unsigned char outbuf_meta[sizeof(file_metadata_t)];
        unsigned long long out_len;
        unsigned char tag;

        size_t n = fread(inbuf_meta, 1, meta_ct_len, fin);
        if (n != meta_ct_len) {
            fprintf(
                stderr, 
                RED "[ERROR] Failed to read metadata ciphertext (got %zu, expected %zu)\n" RESET, n, meta_ct_len
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (crypto_secretstream_xchacha20poly1305_pull(&st, outbuf_meta, &out_len, &tag, inbuf_meta, n, NULL, 0) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] secretstream_pull(meta) failed (tampered?)\n" RESET
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (out_len != sizeof(file_metadata_t)) {
            fprintf(
                stderr,
                RED "[ERROR] Unexpected metadata size: %llu\n" RESET, (unsigned long long)out_len
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        memcpy(&md, outbuf_meta, sizeof(md));
        have_md = 1;
    }

    unsigned char inbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char outbuf[CHUNK_SIZE];
    unsigned long long out_len;
    unsigned char tag;
    int done = 0;

    while (!done) {
        size_t n = fread(inbuf, 1, sizeof inbuf, fin);
        if (n == 0) {
            if (feof(fin)) {
                fprintf(
                    stderr,
                    RED "[ERROR] Unexpected EOF (no FINAL tag)\n" RESET
                );
            } else {
                perror(RED "fread" RESET);
            }
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (crypto_secretstream_xchacha20poly1305_pull(&st, outbuf, &out_len, &tag, inbuf, n, NULL, 0) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] secretstream_pull failed (tampered?)\n" RESET
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (fwrite(outbuf, 1, out_len, fout) != out_len) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to write decrypted chunk\n" RESET
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (tag & crypto_secretstream_xchacha20poly1305_TAG_FINAL) done = 1;
    }

    fclose(fin);
    fclose(fout);

    // Restore metadata if we have it
    if (dec_all && have_md) {
        chmod(tmp_dec_path, (mode_t)md.pmode);
        struct utimbuf times;
        times.actime  = (time_t)md.mtime;
        times.modtime = (time_t)md.mtime;
        utime(tmp_dec_path, &times);
    }

    if (rename(tmp_dec_path, dec_path) != 0) {
        perror("rename");
        return -1;
    }

    if (dec_all && have_md) {
        printf(GREEN "[SUCCESS] File %s and its metadata were successfully decrypted (symmetric)\n" RESET, dec_path);
    } else {
        printf(GREEN "[SUCCESS] File %s was successfully decrypted (symmetric, content only)\n" RESET, dec_path);
    }

    return 0;
}

int encrypt_file_asymmetric(const unsigned char* pub_key, const char* plain_path, const char* enc_path, int enc_all) {
    FILE* fin = fopen(plain_path, "rb");
    if (!fin) {
        perror(RED "fopen plain_path in file encrypt" RESET);
        return -1;
    }

    char tmp_enc_path[1024];
    snprintf(tmp_enc_path, sizeof(tmp_enc_path), "%s.tmp", enc_path);

    FILE* fout = fopen(tmp_enc_path, "wb");
    if (!fout) {
        perror(RED "fopen enc_path in file encrypt" RESET);
        fclose(fin);
        return -1;
    }

    // Per-file secret key for secretstream
    unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    randombytes_buf(file_key, sizeof file_key);

    // Seal file key with server public key
    unsigned char sealed_key[crypto_box_SEALBYTES + sizeof file_key];
    if (crypto_box_seal(sealed_key, file_key, sizeof file_key, pub_key) != 0) {
        fprintf(stderr, "crypto_box_seal failed\n");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    if (fwrite(sealed_key, 1, sizeof sealed_key, fout) != sizeof sealed_key) {
        fprintf(stderr, "Failed to write sealed key\n");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    // Get metadata (always)
    file_metadata_t md = {};
    if (get_file_metadata(plain_path, &md) != 0) {
        fputs(RED "[ERROR] Failed to get file metadata\n" RESET, stderr);
        fclose(fin);
        fclose(fout);
        return -1;
    }

    // Init secretstream
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (crypto_secretstream_xchacha20poly1305_init_push(&st, header, file_key) != 0) {
        fputs(RED "[ERROR] secretstream init_push failed\n" RESET, stderr);
        fclose(fin);
        fclose(fout);
        return -1;
    }

    if (fwrite(header, 1, sizeof header, fout) != sizeof header) {
        fputs(RED "[ERROR] Failed to write header\n" RESET, stderr);
        fclose(fin);
        fclose(fout);
        return -1;
    }

    unsigned long long out_len;

    // Optionally encrypt metadata as first chunk
    if (enc_all) {
        unsigned char meta_ct[sizeof(file_metadata_t) + crypto_secretstream_xchacha20poly1305_ABYTES];

        if (crypto_secretstream_xchacha20poly1305_push(
                &st,
                meta_ct, &out_len,
                (unsigned char*)&md, sizeof(md),
                NULL, 0,
                crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0)
        {
            fprintf(stderr, "secretstream push(meta) failed\n");
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (fwrite(meta_ct, 1, out_len, fout) != out_len) {
            fprintf(stderr, "Failed to write encrypted metadata\n");
            fclose(fin);
            fclose(fout);
            return -1;
        }
    }

    // Encrypt file data
    unsigned char inbuf[CHUNK_SIZE];
    unsigned char outbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t n;
    int is_last;

    for (;;) {
        n = fread(inbuf, 1, CHUNK_SIZE, fin);
        if (ferror(fin)) {
            perror(RED "fread" RESET);
            fclose(fin);
            fclose(fout);
            return -1;
        }

        is_last = feof(fin);

        unsigned char tag = is_last
            ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
            : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        if (crypto_secretstream_xchacha20poly1305_push(
                &st,
                outbuf, &out_len,
                inbuf, n,
                NULL, 0,
                tag) != 0)
        {
            fputs(RED "[ERROR] secretstream_push failed\n" RESET, stderr);
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (fwrite(outbuf, 1, out_len, fout) != out_len) {
            fputs(RED "[ERROR] Failed to write encrypted chunk\n" RESET, stderr);
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (is_last)
            break;
    }

    fclose(fin);
    fclose(fout);

    if (rename(tmp_enc_path, enc_path) != 0) {
        perror(RED "rename" RESET);
        return -1;
    }

    if (enc_all) {
        printf(GREEN "[SUCCESS] File %s and its metadata were successfully encrypted (asymmetric)\n" RESET, enc_path);
    } else {
        printf(GREEN "[SUCCESS] File %s was successfully encrypted (content only + assymetric)\n" RESET, enc_path);
    }

    return 0;
}

int decrypt_file_asymmetric(const unsigned char* pub_key, const unsigned char* pr_key, const char* enc_path, const char* dec_path, int dec_all) {
    FILE *fin = fopen(enc_path, "rb");
    if (!fin) {
        perror("fopen encrypted input");
        return -1;
    }

    char tmp_dec_path[1024];
    snprintf(tmp_dec_path, sizeof(tmp_dec_path), "%s.tmp", dec_path);

    FILE *fout = fopen(tmp_dec_path, "wb");
    if (!fout) {
        perror("fopen output");
        fclose(fin);
        return -1;
    }

    // Read sealed key
    unsigned char sealed_key[crypto_box_SEALBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (fread(sealed_key, 1, sizeof sealed_key, fin) != sizeof sealed_key) {
        fprintf(stderr, "Failed to read sealed key\n");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    // Unseal file key
    unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (crypto_box_seal_open(file_key, sealed_key, sizeof sealed_key, pub_key, pr_key) != 0) {
        fprintf(stderr, "Failed to unseal file key (forged or wrong key)\n");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    // Read header
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if (fread(header, 1, sizeof header, fin) != sizeof header) {
        fprintf(stderr, "Failed to read header\n");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, file_key) != 0) {
        fprintf(stderr, "secretstream init_pull failed\n");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    file_metadata_t md = {};
    int have_md = 0;

    // If metadata was encrypted, read/decrypt that first chunk
    if (dec_all) {
        size_t meta_ct_len = sizeof(file_metadata_t) + crypto_secretstream_xchacha20poly1305_ABYTES;
        unsigned char inbuf_meta[sizeof(file_metadata_t) + crypto_secretstream_xchacha20poly1305_ABYTES];
        unsigned char outbuf_meta[sizeof(file_metadata_t)];
        unsigned long long out_len;
        unsigned char tag;

        size_t n = fread(inbuf_meta, 1, meta_ct_len, fin);
        if (n != meta_ct_len) {
            fprintf(stderr, "Failed to read metadata ciphertext (got %zu, expected %zu)\n",
                    n, meta_ct_len);
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (crypto_secretstream_xchacha20poly1305_pull(
                &st,
                outbuf_meta, &out_len,
                &tag,
                inbuf_meta, n,
                NULL, 0) != 0)
        {
            fprintf(stderr, "secretstream pull(meta) failed (tampered?)\n");
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (out_len != sizeof(file_metadata_t)) {
            fprintf(stderr, "Unexpected metadata size: %llu\n",
                    (unsigned long long)out_len);
            fclose(fin);
            fclose(fout);
            return -1;
        }

        memcpy(&md, outbuf_meta, sizeof(md));
        have_md = 1;
    }

    // Decrypt file contents
    unsigned char inbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char outbuf[CHUNK_SIZE];
    unsigned long long out_len;
    unsigned char tag;
    int done = 0;

    while (!done) {
        size_t n = fread(inbuf, 1, sizeof inbuf, fin);
        if (n == 0) {
            if (feof(fin)) {
                fprintf(stderr, "Unexpected EOF (no FINAL tag)\n");
            } else {
                perror("fread");
            }
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (crypto_secretstream_xchacha20poly1305_pull(
                &st,
                outbuf, &out_len,
                &tag,
                inbuf, n,
                NULL, 0) != 0)
        {
            fputs(RED "[ERROR] secretstream_pull failed (tampered?)\n" RESET, stderr);
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (fwrite(outbuf, 1, out_len, fout) != out_len) {
            fputs(RED "[ERROR] Failed to write decrypted chunk\n" RESET, stderr);
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (tag & crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            done = 1;
        }
    }

    fclose(fin);
    fclose(fout);

    // Restore metadata if we have it
    if (have_md) {
        chmod(dec_path, (mode_t)md.pmode);
        struct utimbuf times;
        times.actime  = (time_t)md.mtime;
        times.modtime = (time_t)md.mtime;
        utime(dec_path, &times);
    }

    if (rename(tmp_dec_path, dec_path) != 0) {
        perror("rename");
        return -1;
    }

    if (dec_all) {
        printf(GREEN "[SUCCESS] File %s and its metadata were successfully decrypted (asymmetric)\n" RESET, dec_path);
    } else {
        printf(GREEN "[SUCCESS] File %s was successfully decrypted (content only + asymmetric)\n" RESET, dec_path);
    }

    return 0;
}