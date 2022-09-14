/**
 * MIT License
 *
 * Copyright (c) 2022 0xfff0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#if defined(__APPLE__) && defined(__MACH__)
    #include <TargetConditionals.h>
    #ifdef TARGET_OS_MAC
        #include <sys/mman.h>
    #else
        #error "Unsupported platform"
    #endif
#elif __linux__
    #include <linux/mman.h>
#else
    #error "Unsupported platform"
#endif

#define KEY_SIZE        256
#define IV_SIZE         128
#define SALT_SIZE       128

#define KEY_LEN_BYTES   (KEY_SIZE/8)
#define IV_LEN_BYTES    (IV_SIZE/8)
#define SALT_LEN_BYTES  (SALT_SIZE/8)


/**
 * ENC_PLAINTEXT_SIZE:
 *
 *      For encryption use 32M chunks (or the remainder of input file)
 */
#define ENC_PLAINTEXT_SIZE   (1UL << 25)

/**
 * ENC_FINAL_CHUNK_SIZE:
 *
 *      For encryption, each chunk of plaintext will become size of
 *      ENC_FINAL_CHUNK_SIZE after encryption and encoding; it consists
 *      of:
 *
 *          - This chunk's initialization vector, in binary cleartext;
 *          - This chunk's key salt, in binary clear text;
 *          - ENC_PLAINTEXT_SIZE of cipher text, since ENC_PLAINTEXT_SIZE
 *            is divisible by AES CBC block size of 16 bytes; therefore,
 *          - extra 16 bytes of PKCS padding;
 */
#define ENC_FINAL_CHUNK_SIZE (IV_LEN_BYTES + SALT_LEN_BYTES + \
                              ENC_PLAINTEXT_SIZE + 16)

/**
 * CHUNK_BUF_SIZE:
 *
 *      Each thread's per-chunk scratch buffer for decryption.  It is
 *      ceil'd to the next 4KB page boundary for memory allocation
 *      alignment.
 */
#define PAGE_SIZE       (1U << 12)
#define CHUNK_BUF_SIZE  ((ENC_FINAL_CHUNK_SIZE + PAGE_SIZE) & ~(PAGE_SIZE - 1))

#define KDF_ITER        10000
#define EVP_OK          1

#define CHECK(_stmt, _msg)                          \
    do {                                            \
        if (!(_stmt)) {                             \
            fprintf(stderr, (_msg "\n"));           \
            exit(1);                                \
        }                                           \
    } while (0)

#define CHECK_ERRNO(_stmt, _prefix)                 \
    do {                                            \
        if (!(_stmt)) {                             \
            perror((_prefix));                      \
            exit(errno);                            \
        }                                           \
    } while (0)

#define CHECK_OPENSSL(_stmt)                        \
    do {                                            \
        if (!(_stmt)) {                             \
            ERR_print_errors_fp(stderr);            \
            exit(1);                                \
        }                                           \
    } while (0)

#define PRINT_STATIC_BYTES(_arr)                    \
    do {                                            \
        short _i;                                   \
        for (_i = 0; _i < sizeof (_arr); _i++) {    \
            printf("%02X", (_arr)[_i]);             \
        }                                           \
    } while (0)


static char enc;
static char verbose;
static char *pass;
static unsigned char *in_mmap_addr;
static unsigned char *out_mmap_addr;
static size_t in_fsize;
static size_t out_fsize_actual;
static size_t out_fsize_max;
static unsigned long sequence_num;

void gen_256_key(         char *passphrase, int p_len,
                 unsigned char *salt,       int s_len,
                 unsigned char *derived)
{
    unsigned char i;
    unsigned char buf[KEY_LEN_BYTES];

    CHECK_OPENSSL(PKCS5_PBKDF2_HMAC(passphrase, p_len,
                                    salt, s_len,
                                    KDF_ITER, EVP_sha256(),
                                    sizeof buf, buf) == EVP_OK);
    for (i = 0; i < sizeof buf; i++) {
        derived[i] = buf[i];
    }
}

void aes_256_cbc_encrypt(unsigned char *plaintext,  int plaintext_len,
                         unsigned char *key,        unsigned char *iv,
                         unsigned char *ciphertext, int *ciphertext_len)
{
    int written = 0;
    EVP_CIPHER_CTX *ctx;

    CHECK_OPENSSL((ctx = EVP_CIPHER_CTX_new()) != NULL);
    CHECK_OPENSSL(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) == EVP_OK);
    CHECK_OPENSSL(EVP_EncryptUpdate(ctx, ciphertext, &written,
                                    plaintext, plaintext_len) == EVP_OK);
    *ciphertext_len = written;
    CHECK(*ciphertext_len >= 0, "Unexpected EVP return value.");

    CHECK_OPENSSL(EVP_EncryptFinal_ex(ctx, ciphertext + written, &written) == EVP_OK);
    *ciphertext_len += written;
    CHECK(*ciphertext_len >= 0, "Unexpected EVP return value.");

    EVP_CIPHER_CTX_free(ctx);
}

void aes_256_cbc_decrypt(unsigned char *ciphertext, int ciphertext_len,
                         unsigned char *key,        unsigned char *iv,
                         unsigned char *plaintext,  int *plaintext_len)
{
    int written = 0;
    EVP_CIPHER_CTX *ctx;

    CHECK_OPENSSL((ctx = EVP_CIPHER_CTX_new()) != NULL);
    CHECK_OPENSSL(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) == EVP_OK);
    CHECK_OPENSSL(EVP_DecryptUpdate(ctx, plaintext, &written,
                                    ciphertext, ciphertext_len) == EVP_OK);
    *plaintext_len = written;
    CHECK(*plaintext_len >= 0, "Unexpected EVP return value.");

    CHECK_OPENSSL(EVP_DecryptFinal_ex(ctx, plaintext + written, &written) == EVP_OK);
    *plaintext_len += written;
    CHECK(*plaintext_len >= 0, "Unexpected EVP return value.");

    EVP_CIPHER_CTX_free(ctx);
}

static void *worker(void *unused)
{
    unsigned char *in_start_addr, *out_start_addr, *scratch;
    unsigned char salt[SALT_LEN_BYTES];
    unsigned char iv[IV_LEN_BYTES];
    unsigned char key[KEY_LEN_BYTES];
    unsigned bytes_in_exp, bytes_in_actual;
    unsigned bytes_out_exp;
    unsigned num_bytes;
    unsigned long my_seq;
    unsigned long read_offset;

    bytes_in_exp  = enc ? ENC_PLAINTEXT_SIZE   : ENC_FINAL_CHUNK_SIZE;
    bytes_out_exp = enc ? ENC_FINAL_CHUNK_SIZE : ENC_PLAINTEXT_SIZE;

    if (!enc) {
        /**
         * XXX: For decryption the data must be first written to a local buffer instead
         *      of the mmap'd region directly.  This is because the decrypted text
         *      initially contains padding that will be truncated by the finalize
         *      function; only then can we transfer the result to the output memory
         *      location, otherwise we'd end up corrupting next chunk's data. 
         */
        CHECK_ERRNO(posix_memalign((void **)&scratch, PAGE_SIZE, CHUNK_BUF_SIZE) == 0, "posix_memalign");
    }

    while (1) {
        my_seq = __atomic_fetch_add(&sequence_num, 1, __ATOMIC_SEQ_CST);

        read_offset = (unsigned long)my_seq * bytes_in_exp;
        if (read_offset >= in_fsize) {
            break;
        }
        in_start_addr  = in_mmap_addr  + read_offset;
        out_start_addr = out_mmap_addr + (unsigned long)bytes_out_exp * my_seq;

        bytes_in_actual = read_offset + bytes_in_exp < in_fsize ? bytes_in_exp : in_fsize - read_offset;

        /**
         * For each chunk for encryption, data is stored back to disk in this format:
         *
         *      +----+------+--------------------+
         *      | IV | Salt | Encrypted data ... |
         *      +----+------+--------------------+
         *
         * where:
         *
         *      - IV                   : initialization vector in byte array, with length
         *                               of IV_LEN_BYTES.
         *      - Salt                 : salt used for key derivation in byte array, with
         *                               length of SALT_LEN_BYTES.
         *      - Encrypted data       : encrypted data; see notes on ENC_FINAL_CHUNK_SIZE.
         */ 
        if (enc) {
            CHECK(RAND_bytes(salt, sizeof salt) == EVP_OK, "Failed to retrieve nonce");
            CHECK(RAND_bytes(  iv,   sizeof iv) == EVP_OK, "Failed to retrieve nonce");
            gen_256_key(pass, strlen(pass), salt, sizeof salt, key);
            aes_256_cbc_encrypt(in_start_addr, bytes_in_actual, key, iv,
                                out_start_addr + IV_LEN_BYTES + SALT_LEN_BYTES, (int *)&num_bytes);
            CHECK(num_bytes == ENC_PLAINTEXT_SIZE + 16 || bytes_in_exp > bytes_in_actual,
                  "Unexpected cipher text length.");

            memcpy((void *)out_start_addr, (void *)iv, IV_LEN_BYTES);
            memcpy((void *)out_start_addr + IV_LEN_BYTES, (void *)salt, SALT_LEN_BYTES);

            num_bytes += IV_LEN_BYTES + SALT_LEN_BYTES;
        } else {
            memcpy((void *)iv, (void *)in_start_addr, IV_LEN_BYTES);
            memcpy((void *)salt, (void *)(in_start_addr + IV_LEN_BYTES), SALT_LEN_BYTES);
            gen_256_key(pass, strlen(pass), salt, sizeof salt, key);
            aes_256_cbc_decrypt(in_start_addr + IV_LEN_BYTES + SALT_LEN_BYTES,
                                bytes_in_actual - IV_LEN_BYTES - SALT_LEN_BYTES,
                                key, iv, scratch, (int *)&num_bytes);
            memcpy((void *)out_start_addr, (void *)scratch, num_bytes);
            CHECK(num_bytes == ENC_PLAINTEXT_SIZE || bytes_in_exp > bytes_in_actual,
                  "Unexpected plaintext length.");
        }
        __atomic_fetch_add(&out_fsize_actual, num_bytes, __ATOMIC_SEQ_CST);

        if (verbose) {
            printf("Chunk %5lu: encoded size %10u S/IV: ", my_seq, num_bytes);
            PRINT_STATIC_BYTES(salt); printf("/"); PRINT_STATIC_BYTES(iv);
            printf("\n");
        }
    }

    /* Skip free's */
    return NULL;
}

int main(int argc, char **argv)
{
    int i, c, in_fd, out_fd;
    char *in_fname = NULL;
    char *out_fname = NULL;
    short concurrency = 0;
    struct stat fs;

    pthread_t *threads;

    while ((c = getopt(argc, argv, "j:i:o:p:v")) != -1) {
        switch (c) {
        case 'j':
            concurrency = atoi(optarg);
            break;
        case 'i':
            in_fname = optarg;
            break;
        case 'o':
            out_fname = optarg;
            break;
        case 'p':
            pass = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case '?':
        default:
            abort();
        }
    }
    if (concurrency == 0) {
        concurrency = sysconf(_SC_NPROCESSORS_ONLN);
    }
    CHECK(optind < argc, "Missing mode (dec/enc).");
    CHECK(in_fname && out_fname, "Missing input/output file.");
    CHECK(concurrency > 0 && concurrency < 128, "Invalid job count.");

    if (strncmp("enc", argv[optind], 3) == 0) {
        enc = 1;
    } else if (strncmp("dec", argv[optind], 3) == 0) {
        enc = 0;
    } else {
        fprintf(stderr, "Invalid input.\n");
        return 1;
    }

    if (!pass) {
        pass = getpass("Passphrase: ");                     // XXX: getpass() obsolete
    }
    CHECK(pass && strlen(pass), "invalid passphrase.");     // XXX: ascii only

    in_fd = open(in_fname, O_RDONLY);
    CHECK_ERRNO(in_fd != -1, "open()");
    CHECK_ERRNO(fstat(in_fd, &fs) != -1, "fstat()");
    in_fsize = fs.st_size;
    in_mmap_addr = mmap(NULL, in_fsize, PROT_WRITE, MAP_PRIVATE, in_fd, 0);
    CHECK_ERRNO(in_mmap_addr != MAP_FAILED, "mmap() input");

    out_fd = open(out_fname, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    CHECK_ERRNO(out_fd != -1, "open()");

    out_fsize_max = (in_fsize / ENC_FINAL_CHUNK_SIZE + 1) * ENC_FINAL_CHUNK_SIZE;
#ifndef TARGET_OS_MAC
    CHECK_ERRNO(posix_fallocate(out_fd, 0, out_fsize_max) == 0, "fallocate()");
#else
    /**
     * posix_fallocate() is not available on macOS; simulate file allocation by
     * creating a sparse file.
     */
    CHECK(lseek(out_fd, out_fsize_max - 1, SEEK_SET) == out_fsize_max - 1 &&
          write(out_fd, "\0", 1) == 1, "Unable to allocate output file.");
#endif

    out_mmap_addr = mmap(NULL, out_fsize_max, PROT_WRITE, MAP_SHARED, out_fd, 0);
    CHECK_ERRNO(out_mmap_addr != MAP_FAILED, "mmap() output");

    CHECK((threads = malloc(concurrency * sizeof(*threads))) != NULL,
          "Unable to allocate pthreads.");

    for (i = 0; i < concurrency; i++) {
        CHECK_ERRNO(pthread_create(&threads[i], NULL, worker, NULL) == 0, "pthread_create()");
    }
    for (i = 0; i < concurrency; i++) {
        CHECK_ERRNO(pthread_join(threads[i], NULL) == 0, "pthread_join()");
    }

    munmap(in_mmap_addr, in_fsize);
    munmap(out_mmap_addr, out_fsize_max);

    CHECK_ERRNO(ftruncate(out_fd, out_fsize_actual) == 0, "ftruncate()");
    if (verbose) {
        printf("Total bytes written: %lu\n", out_fsize_actual);
    }

    close(in_fd);
    close(out_fd);

    /* Skip free's */
    return 0;
}
