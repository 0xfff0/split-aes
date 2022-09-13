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
 **/

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#define KEY_SIZE        256
#define IV_SIZE         128
#define SALT_SIZE       128

#define KEY_LEN_BYTES   (KEY_SIZE/8)
#define IV_LEN_BYTES    (IV_SIZE/8)
#define SALT_LEN_BYTES  (SALT_SIZE/8)

#define ENC_CHUNK_SIZE  (1024 * 1024 * 32)

/**
 * To account for additional data during encryption, the chunk buffer size
 * is slightly larger than the input chunk size.  From EVP_EncryptUpdate:
 *
 * "... the amount of data written can be anything from zero bytes
 * to (inl + cipher_block_size - 1) bytes."
 */
#define PAGE_SIZE       (1U << 12)
#define CHUNK_BUF_SIZE  ((ENC_CHUNK_SIZE + PAGE_SIZE) & ~(PAGE_SIZE - 1))

#define KDF_ITER        10000
#define EVP_OK          1

#define CHECK(_stmt, _msg)                          \
    do {                                            \
        if (!(_stmt)) {                             \
            fprintf(stderr, (_msg));                \
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


static pthread_mutex_t read_lock;
static pthread_mutex_t write_lock;
static pthread_cond_t write_cond;

static FILE *in_fp;
static FILE *out_fp;
static char enc;
static char verbose;
static char *pass;
static unsigned sequence;
static unsigned next_write_sequence;

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
    CHECK_OPENSSL(EVP_EncryptUpdate(ctx, ciphertext, &written, plaintext, plaintext_len) == EVP_OK);
    *ciphertext_len = written;
    CHECK(*ciphertext_len >= 0, "Unexpected EVP return value.\n");

    CHECK_OPENSSL(EVP_EncryptFinal_ex(ctx, ciphertext + written, &written) == EVP_OK);
    *ciphertext_len += written;
    CHECK(*ciphertext_len >= 0, "Unexpected EVP return value.\n");

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
    CHECK_OPENSSL(EVP_DecryptUpdate(ctx, plaintext, &written, ciphertext, ciphertext_len) == EVP_OK);
    *plaintext_len = written;
    CHECK(*plaintext_len >= 0, "Unexpected EVP return value.\n");

    CHECK_OPENSSL(EVP_DecryptFinal_ex(ctx, plaintext + written, &written) == EVP_OK);
    *plaintext_len += written;
    CHECK(*plaintext_len >= 0, "Unexpected EVP return value.\n");

    EVP_CIPHER_CTX_free(ctx);
}

static void *worker(void *unused)
{
    unsigned char *input_data;
    unsigned char *output_data;
    unsigned char salt[SALT_LEN_BYTES];
    unsigned char iv[IV_LEN_BYTES];
    unsigned char key[KEY_LEN_BYTES];
    unsigned bytes_read, bytes_written;
    unsigned curr_chunk_size;
    unsigned my_seq;

    CHECK_ERRNO(posix_memalign( (void **)&input_data, PAGE_SIZE, CHUNK_BUF_SIZE) == 0, "posix_memalign(): ");
    CHECK_ERRNO(posix_memalign((void **)&output_data, PAGE_SIZE, CHUNK_BUF_SIZE) == 0, "posix_memalign(): ");

    while (1) {
        CHECK_ERRNO(pthread_mutex_lock(&read_lock) == 0, "pthread_mutex_lock (read): ");
        if((bytes_read = fread(input_data, 1, enc ? ENC_CHUNK_SIZE : 4, in_fp)) > 0) {
            my_seq = sequence++;
            if (!enc) {
                curr_chunk_size = *(unsigned *)input_data;
                CHECK(curr_chunk_size < CHUNK_BUF_SIZE, "Input chunk is too large to fit in buffer.\n");

                bytes_read = fread(input_data + 4, 1, curr_chunk_size - 4, in_fp);
                CHECK(bytes_read == curr_chunk_size - 4, "Unable to read from file input.\n");
            }
        }
        CHECK_ERRNO(pthread_mutex_unlock(&read_lock) == 0, "pthread_mutex_unlock (read): ");
        if (bytes_read == 0) {
            break;
        }

        /**
         * For each chunk for encryption, data is stored back to disk in this format:
         *
         *      +------------------+----+------+--------------------+
         *      | Total chunk size | IV | Salt | Encrypted data ... |
         *      +------------------+----+------+--------------------+
         *
         * where:
         *
         *      - Total chunk size (4B): the total size of this chunk in bytes, including
         *                               the field itself.
         *      - IV                   : initialization vector in byte array, with length
         *                               of IV_LEN_BYTES.
         *      - Salt                 : salt used for key derivation in byte array, with
         *                               length of SALT_LEN_BYTES.
         *      - Encrypted data       : encrypted data; the size of which can be
         *                               calculated by (Total chunk size - 4 - IV - Salt)
         */ 
        if (enc) {
            CHECK(RAND_bytes(salt, sizeof salt) == EVP_OK, "Failed to retrieve nonce");
            CHECK(RAND_bytes(  iv,   sizeof iv) == EVP_OK, "Failed to retrieve nonce");
            gen_256_key(pass, strlen(pass), salt, sizeof salt, key);
            aes_256_cbc_encrypt(input_data, bytes_read, key, iv,
                                output_data + IV_LEN_BYTES + SALT_LEN_BYTES + 4, (int *)&bytes_written);
            curr_chunk_size = IV_LEN_BYTES + SALT_LEN_BYTES + bytes_written + 4;

            memcpy((void *)output_data, (void *)&curr_chunk_size, 4);
            memcpy((void *)output_data + 4, (void *)iv, IV_LEN_BYTES);
            memcpy((void *)output_data + 4 + IV_LEN_BYTES, (void *)salt, SALT_LEN_BYTES);
        } else {
            memcpy((void *)iv, (void *)(input_data + 4), IV_LEN_BYTES);
            memcpy((void *)salt, (void *)(input_data + 4 + IV_LEN_BYTES), SALT_LEN_BYTES);
            gen_256_key(pass, strlen(pass), salt, sizeof salt, key);
            aes_256_cbc_decrypt(input_data + 4 + IV_LEN_BYTES + SALT_LEN_BYTES,
                                curr_chunk_size - 4 - IV_LEN_BYTES - SALT_LEN_BYTES,
                                key, iv, output_data, (int *)&bytes_written);
            curr_chunk_size = bytes_written;
        }

        if (verbose) {
            printf("Chunk %5u: encoded size %10u S/IV: ", my_seq, curr_chunk_size);
            PRINT_STATIC_BYTES(salt); printf("/"); PRINT_STATIC_BYTES(iv);
            printf("\n");
        }

        CHECK_ERRNO(pthread_mutex_lock(&write_lock) == 0, "pthread_mutex_lock (write): ");
        while (next_write_sequence != my_seq) {
            CHECK_ERRNO(pthread_cond_wait(&write_cond, &write_lock) == 0, "pthread_cond_wait: ");
        }

        fwrite(output_data, 1, curr_chunk_size, out_fp);
        next_write_sequence++;

        CHECK_ERRNO(pthread_mutex_unlock(&write_lock) == 0, "pthread_mutex_unlock (write): ");
        CHECK_ERRNO(pthread_cond_broadcast(&write_cond) == 0, "pthread_cond_broadcast: ");
    }

    /* Skip free's */
    return NULL;
}

int main(int argc, char **argv)
{
    int i, c;
    char *in_fname = NULL;
    char *out_fname = NULL;
    short concurrency = 0;

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
        concurrency = sysconf(_SC_NPROCESSORS_ONLN) * 2;
    }
    CHECK(optind < argc, "Missing mode (dec/enc).\n");
    CHECK(in_fname && out_fname, "Missing input/output file.\n");
    CHECK(concurrency > 0 && concurrency < 128, "Invalid job count.\n");

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
    CHECK(pass && strlen(pass), "invalid passphrase.\n");   // XXX: ascii only

    CHECK_ERRNO((in_fp  = fopen(in_fname,  "rb")) != NULL, "Input file: ");
    CHECK_ERRNO((out_fp = fopen(out_fname, "wb")) != NULL, "Output file: ");

    CHECK((threads = malloc(concurrency * sizeof(*threads))) != NULL,
          "Unable to allocate pthreads.\n");

    CHECK_ERRNO(pthread_mutex_init( &read_lock, NULL) == 0, "pthread_mutex_init (read): ");
    CHECK_ERRNO(pthread_mutex_init(&write_lock, NULL) == 0, "pthread_mutex_init (write): ");
    CHECK_ERRNO(pthread_cond_init( &write_cond, NULL) == 0, "pthread_cond_init: ");

    for (i = 0; i < concurrency; i++) {
        CHECK_ERRNO(pthread_create(&threads[i], NULL, worker, NULL) == 0, "pthread_create: ");
    }
    for (i = 0; i < concurrency; i++) {
        CHECK_ERRNO(pthread_join(threads[i], NULL) == 0, "pthread_join: ");
    }
    fclose(in_fp);
    fclose(out_fp);

    /* Skip free's */
    return 0;
}
