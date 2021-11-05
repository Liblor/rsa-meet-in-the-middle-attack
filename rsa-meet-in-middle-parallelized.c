/**
 * Meet in the middle attack on Textbook RSA
 * Loris Reiff <loris.reiff@liblor.ch>
 * 2021-11-04
 *
 * Reference:
 * Boneh D., Joux A., Nguyen P.Q. (2000) Why Textbook ElGamal and RSA
 * Encryption Are Insecure.
 *
 * Note: For larger messages (i.e. L) additional swap might be required
 *
 */

#define NUM_THREADS 10
#define MIN(x,y) ((x) < (y) ? (x) : (y))

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <gmp.h>


static const char *CIPHERTEXT = // base 16
    ("382ed82bad6afb2f789f5078b058c939a1e94a5bc7d4fc0e9c346418fda0cc95886ba4a"
     "20efe921482829839e2163f945e7cc04cc319b3ca0a8a78ca6ed1b2feeb97ea40a7aa1d"
     "c705a722b9a2605877809915b");

static const char *N = // base 10
    ("38268664315844449075926253758060306191986182502270296650968512313561046"
     "51628384629975111689738391393872672317305934874128000449244952040977576"
     "80232772228733125618598449291877751388758432792252179470197");

/* Private key:
 * d = ("11022744042147117890752702934081578344845250272294374015904490699041"
 *      "63869398797879976809792440783287819189252777386882105127045286886091"
 *      "25115421115850811914142401785895152103499686385340140798997839229")
*/
static uint32_t L = 12;
static uint32_t E = 65537;


struct precalc {
    // val == pow(i,e) mod N
    size_t i;
    mpz_t val;
};

struct build_table_thread_args {
    struct precalc *table;
    size_t start;
    size_t end;
    const mpz_t *e;
    const mpz_t *n;
};

struct meet_in_the_middle_thread_args {
    const mpz_t *c;
    const struct precalc *arr;
    size_t size;
    size_t start;
    size_t end;
    const mpz_t *e;
    const mpz_t *n;
    volatile bool *stop;
    mpz_t *res;
};

static struct precalc *alloc_table(
        size_t size
) {
    if (size * sizeof(struct precalc) <= size) { return NULL; }
    struct precalc *table = malloc(size * sizeof(struct precalc));
    if (!table) { return NULL; }
    for (size_t i = 0; i < size; i++) {
        mpz_init(table[i].val);
    }
    return table;
}

static void free_table(
        struct precalc *table,
        size_t size
) {
    for (size_t i = 0; i < size; i++) {
        mpz_clear(table[i].val);
    }
    free(table);
}

static ssize_t binary_search(
        const struct precalc *arr,
        const mpz_t x,
        size_t size
) {
    size_t low = 0;
    size_t high = size - 1;
    size_t mid = 0;
    while (low <= high) {
        mid = low + (high - low) / 2;
        if (mpz_cmp(arr[mid].val, x) < 0) {
            low = mid + 1;
        } else if (mpz_cmp(arr[mid].val, x) > 0) {
            high = mid - 1;
        } else {
            return (ssize_t) mid;
        }
    }
    return (ssize_t)(-1);
}

static inline void build_table(
        struct precalc *arr,
        size_t start,
        size_t end,
        const mpz_t e,
        const mpz_t n
) {
    mpz_t ii; mpz_init(ii);
    for (size_t i = start; i < end; i++) {
        mpz_set_ui(ii, i+1);
        arr[i].i = i+1;
        mpz_powm(arr[i].val, ii, e, n);
    }
    mpz_clear(ii);
}

static inline int compare_precalc(
        const void *p1,
        const void *p2
) {
    struct precalc *ptr1 = (struct precalc *) p1;
    struct precalc *ptr2 = (struct precalc *) p2;
    return mpz_cmp(ptr1->val, ptr2->val);
}

/**
 * Textbook RSA meet in the middle attack according to Boneh, Joux & Nguyen.
 *
 * Returns 0 if successful
 */
static int rsa_meet_in_the_middle(
        const mpz_t c,
        const struct precalc *arr,
        size_t size,
        size_t start,
        size_t end,
        const mpz_t e,
        const mpz_t n,
        volatile bool *stop,
        mpz_t res
) {
    mpz_t ii; mpz_init(ii);
    mpz_t s; mpz_init(s);
    mpz_t tmp; mpz_init(tmp);
    ssize_t idx = -1;
    for (size_t i = start; i < end; i++) {
        mpz_set_ui(ii, i+1);
        // s = c * ii^(-e)
        mpz_powm(tmp, ii, e, n);
        mpz_invert(tmp, tmp, n);
        mpz_mul(s, c, tmp);
        mpz_mod(s, s, n);
        idx = binary_search(arr, s, size);
        if (idx != -1 || *stop) { break; }
    }

    if (idx != -1) {
        mpz_set_ui(tmp, arr[idx].i);
        mpz_mul(res, ii, tmp);
        *stop = true;
    }
    mpz_clear(tmp);
    mpz_clear(s);
    mpz_clear(ii);
    return idx == -1;
}


static void *build_table_thread(void *args) {
    struct build_table_thread_args *targs = args;
    build_table(
            targs->table,
            targs->start,
            targs->end,
            *(targs->e),
            *(targs->n));
    return NULL;
}

static void *rsa_meet_in_the_middle_thread(void *args) {
    struct meet_in_the_middle_thread_args *targs = args;
    targs->res = malloc(sizeof(mpz_t));
    if (!targs->res) {
        *(targs->stop) = true;
        perror("Allocation failed\n");
        return NULL;
    }
    mpz_init(*targs->res);
    int r = rsa_meet_in_the_middle(
            *(targs->c),
            targs->arr,
            targs->size,
            targs->start,
            targs->end,
            *(targs->e),
            *(targs->n),
            targs->stop,
            *(targs->res));
    if (r) {
        free(targs->res);
        targs->res = NULL;
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    printf("[+] Program started\n");
    mpz_t e; mpz_init(e); mpz_set_ui(e, E);
    mpz_t n; mpz_init(n); mpz_set_str(n, N, 10);
    mpz_t ciphertext; mpz_init(ciphertext);
    mpz_set_str(ciphertext, CIPHERTEXT, 16);
    mpz_t *m = NULL;

    printf("[+] Allocating memory\n");
    size_t table_size = 1UL << (uint64_t)L/2;
    struct precalc *table = alloc_table(table_size);
    if (table == NULL) {
        perror("Allocation failed\n");
        return 1;
    }

    printf("[+] Calculating table entries\n");
    pthread_t tids[NUM_THREADS];
    struct build_table_thread_args args[NUM_THREADS];
    size_t range = (table_size + NUM_THREADS - 1) / NUM_THREADS;
    for (size_t i = 0; i < NUM_THREADS; i++) {
        args[i].table = table;
        args[i].start = i * range;
        args[i].end = MIN((i + 1) * range, table_size);
        args[i].e = (const mpz_t *)&e;
        args[i].n = (const mpz_t *)&n;
        pthread_create(&tids[i], NULL, build_table_thread, &args[i]);
    }
    for (size_t i = 0; i < NUM_THREADS; i++) {
        pthread_join(tids[i], NULL);
    }


    printf("[+] Sorting the table\n");
    qsort(table, table_size, sizeof(struct precalc), &compare_precalc);

    printf("[+] Performing meet-in-the-middle lookup\n");
    volatile bool stop = false;
    struct meet_in_the_middle_thread_args mitm_args[NUM_THREADS];
    for (size_t i = 0; i < NUM_THREADS; i++) {
        mitm_args[i].c = (const mpz_t *)&ciphertext;
        mitm_args[i].arr = table;
        mitm_args[i].size = table_size;
        mitm_args[i].start = i * range;
        mitm_args[i].end = MIN((i + 1) * range, table_size);
        mitm_args[i].e = (const mpz_t *)&e;
        mitm_args[i].n = (const mpz_t *)&n;
        mitm_args[i].stop = &stop;
        mitm_args[i].res = NULL;
        pthread_create(&tids[i], NULL, rsa_meet_in_the_middle_thread, &mitm_args[i]);
    }
    for (size_t i = 0; i < NUM_THREADS; i++) {
        pthread_join(tids[i], NULL);
        if (mitm_args[i].res) {
            m = mitm_args[i].res;
        }
    }
    if (!m) {
        printf("[-] Meet-in-the-middle attack failed\n");
        free_table(table, table_size);
        return 1;
    }

    printf("[+] Recovered message:\n");
    mpz_out_str(stdout, 10, *m);
    printf("\n");

    free_table(table, table_size);
    mpz_clear(*m);
    free(m);
    mpz_clear(ciphertext);
    mpz_clear(n);
    mpz_clear(e);
    return 0;
}
