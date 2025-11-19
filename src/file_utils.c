#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sodium.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include <sodium/core.h>
#include <sodium/utils.h>
#include <sodium/crypto_generichash.h>
#include <sodium/randombytes.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include "../include/key_utils.h"
#include "../include/file_utils.h"

int hash_file_contents(crypto_generichash_state* state, const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        perror(RED "fopen" RESET);
        return -1;
    }

    unsigned char buf[4096];
    size_t n;
    while((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (crypto_generichash_update(state, buf, (unsigned long long)n) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] crypto_generichash_update failed\n" RESET 
            );
            fclose(f);
            return -1;
        }
    }

    if (ferror(f)) {
        perror(RED "fread" RESET);
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

int get_file_metadata(const char* path, file_metadata_t* fmd) {
    struct stat st;
    if (stat(path, &st) != 0) {
        perror(RED "stat" RESET);
        return -1;
    }

    fmd->size = (uint64_t)st.st_size;
    fmd->mtime = (uint64_t)st.st_mtime;
    fmd->pmode = (uint32_t)st.st_mode;

    return 0;
}

int create_file_mac(const unsigned char *key, const char* path, unsigned char* mac, size_t mac_len) {
    file_metadata_t fmd;
    if (get_file_metadata(path, &fmd) != 0) return -1;

    crypto_generichash_state state;
    if (crypto_generichash_init(&state, key, sizeof(key), mac_len) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] crypto_generichash_init failed\n" RESET
        );
        return -1;
    }

    if (hash_file_contents(&state, path) != 0) return -1;

    if (crypto_generichash_update(&state, (const unsigned char*)&fmd, sizeof(fmd)) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] crypto_generichash_update metadata failed\n" RESET
        );
        return -1;
    }

    if (crypto_generichash_final(&state, mac, mac_len) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] crypto_generichash_final failed\n" RESET
        );
        return -1;
    }

    return 0;
}

int load_file_mac(const char* mac_path, unsigned char* mac, size_t mac_len) {
    FILE* f = fopen(mac_path, "r");
    if (!f) {
        perror(RED "fopen MAC file"RESET);
        return -1;
    }

    char hex[1024];
    if (!fgets(hex, sizeof(hex), f)) {
        perror(RED "fgets" RESET);
        fclose(f);
        return -1;
    }

    size_t len = strcspn(hex, "\r\n");
    hex[len] = '\0';

    size_t mac_read_len = 0;
    if (sodium_hex2bin(mac, mac_len, hex, len, NULL, &mac_read_len, NULL) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] sodium_hex2bin failed\n" RESET
        );
        return -1;
    }

    if (mac_read_len != mac_len) {
        fprintf(
            stderr,
            RED "[ERROR] MAC length mismatch: expected %zu, got %zu\n" RESET, mac_len, mac_read_len
        );
        return -1;
    }

    return 0;
}

int save_file_mac(const char* mac_path, const unsigned char *mac, size_t mac_len) {
    FILE* f = fopen(mac_path, "w");
    if (!f) {
        perror(RED "fopen MAC file" RESET);
        return -1;
    }

    char *hex = sodium_malloc(mac_len*2+1);
    if (!hex) {
        fprintf(
            stderr,
            RED "[ERROR] sodium_malloc failed\n" RESET
        );
        return -1;
    }

    sodium_bin2hex(hex, mac_len*2+1, mac,mac_len);

    fprintf(
        f,
        "%s\n", hex
    );

    sodium_free(hex);
    fclose(f);

    return 0;
}

// Sign file for integrity check
int sign_file(const unsigned char* key, const char* file, const char* mac_file, unsigned char* mac, size_t mac_len) {
    if (create_file_mac(key, file, mac, mac_len) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] Failed to find MAC\n" RESET
        );
        return -1;
    }

    if (save_file_mac(mac_file, mac, mac_len) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] Failed to save MAC hex\n" RESET
        );
        return -1;
    }

    printf(GREEN "[SUCCESS] MAC created and saved to %s\n" RESET, mac_file);
    return 0;
}

// Verify file integrity
int verify_file(const unsigned char* key, const char* file, const char* mac_file, unsigned char* mac, size_t mac_len) {
    unsigned char stored_mac[crypto_generichash_BYTES];
    if (load_file_mac(mac_file, stored_mac, sizeof(stored_mac)) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] Failed to load stored MAC\n" RESET
        );
        return -1;
    }

    if (create_file_mac(key, file, mac, mac_len) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] Failed to find MAC\n" RESET
        );
        return -1;
    }

    if (sodium_memcmp(mac, stored_mac, mac_len) == 0) {
        printf(GREEN "[SUCCESS] File contents and metadata are consistent\n" RESET);
        return 0;
    } else {
        printf(RED "[ERROR] File has been modified\n" RESET);
        return -1;
    }
}

// Encrypt file data with symmetric key + automatic integrity check of file contents
int encrypt_file_symmetric(const unsigned char* key, const char* plain_path, const char* enc_path) {
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

    file_metadata_t md;
    if (get_file_metadata(plain_path, &md) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] Failed to get file metadata\n" RESET
        );
        return -1;
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

    unsigned char inbuf[CHUNK_SIZE];
    unsigned char outbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t n;
    int is_last;

    for (;;) {
        n = fread(inbuf, 1, CHUNK_SIZE, fin);
        is_last = feof(fin);

        unsigned char tag = is_last 
        ? crypto_secretstream_xchacha20poly1305_TAG_FINAL 
        : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long out_len = 0;

        if(crypto_secretstream_xchacha20poly1305_push(&st, outbuf, &out_len, inbuf, n, NULL, 0, tag) != 0) {
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

    printf(GREEN "[SUCCESS] File %s was successfully encrypted\n" RESET, enc_path);

    return 0;
}

// Decrypt file data with symmetric key + automatic integrity check of file contents
int decrypt_file_symmetric(const unsigned char* key, const char* enc_path, const char* dec_path) {
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

    file_metadata_t md;
    if (get_file_metadata(enc_path, &md) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] Failed to get file metadata\n" RESET
        );
        return -1;
    }

    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (fread(header, 1, sizeof(header), fin) != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        if (feof(fin)) {
            fprintf(stderr, RED "[ERROR] Encrypted file is too short\n" RESET);
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

    unsigned char inbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char outbuf[CHUNK_SIZE];
    size_t n;
    int is_last;

    for(;;) {
        n = fread(inbuf, 1, CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES, fin);
        is_last = feof(fin);

        unsigned char tag = is_last 
        ? crypto_secretstream_xchacha20poly1305_TAG_FINAL 
        : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long out_len = 0;

        if (crypto_secretstream_xchacha20poly1305_pull(&st, outbuf, &out_len, &tag, inbuf, n, NULL, 0) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] secretstream_pull failed\n" RESET
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

    if (rename(tmp_dec_path, dec_path) != 0) {
        perror("rename");
        return -1;
    }

    printf(GREEN "[SUCCESS] File %s was successfully decrypted\n" RESET, dec_path);

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
    file_metadata_t md;
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
        printf(GREEN "[SUCCESS] File %s and its metadata were successfully encrypted\n" RESET, enc_path);
    } else {
        printf(GREEN "[SUCCESS] File %s was successfully encrypted (content only)\n" RESET, enc_path);
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

    file_metadata_t md;
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
        printf(GREEN "[SUCCESS] File %s and its metadata were successfully decrypted\n" RESET, dec_path);
    } else {
        printf(GREEN "[SUCCESS] File %s was successfully decrypted (content only)\n" RESET, dec_path);
    }

    return 0;
}