#ifdef ALLINONE
#include <stdlib.h>		/* exit() */
#include <stdio.h>		/* printf() etc. */
#include <unistd.h>		/* access(), read(), close(), getcwd() */
#include <string.h>		/* strlen() etc. */
#include <getopt.h>		/* getopt_long() */
#include <libgen.h>		/* basename() */
#include <fcntl.h>		/* open() */
#include <ftw.h>		/* ftw() */
#include <time.h>		/* time() */
#include <openssl/sha.h>	/* SHA1(), SHA_DIGEST_LENGTH */
#ifndef NO_THREADS
#include <pthread.h>		/* pthread functions and data structures */
#endif
#endif

#include <stdlib.h>
#include <errno.h>

#define xmalloc(s) malloc(s)

#define error_exit(err, str) do { perror(str); exit(err); } while (0)

#define MKTD_DEBUG 0
#define MKTD_INFO 1

#define MKTD_LOG(log_level, str...) \
do {\
	if (log_level >= mktd_loglevel && partial && debug_stream) { \
		fprintf(debug_stream, str); \
		fflush(debug_stream); \
	} \
} while (0)

/* define the type of a file list node */
struct fl_node_s;
typedef struct fl_node_s *fl_node;
struct fl_node_s {
	char *path;
	off_t size;
	off_t hashed;
	unsigned char pending;
	fl_node next;
};

/* global variables */

extern FILE *debug_stream;
extern char *logfile;

/* options */
extern size_t piece_length;	/* piece length */
extern char *announce_url;	/* announce URL */
extern char *comment;		/* optional comment to add to the metainfo */
extern char *torrent_name;	/* name of the torrent (name of directory) */
extern char *metainfo_file_path;	/* absolute path to the metainfo file */
extern char *directory_name;
extern int target_is_directory;	/* target is a directory not just a single file */
extern int no_creation_date;	/* don't write the creation date */
extern int private;		/* set the private flag */
extern int verbose;		/* be verbose */
extern int partial;
extern int finish;
extern int remove_op;
extern int mktd_loglevel;
extern int daemon_start;

/* information calculated by read_dir() */
extern unsigned long long torrent_size;	/* combined size of all files in the torrent */
extern fl_node file_list;	/* list of files and their individual sizes */
extern unsigned int pieces;	/* number of pieces */
extern unsigned int hash_items_count;
extern void lock_flist(void);
extern void unlock_flist(void);

extern unsigned char *final_hash(void);
extern void hash_blocks(int nr, int flush);
extern void unhash_from(int blk);
extern int flnode_open(fl_node node, int flags);
extern void MKTD_LOG_dump_node(fl_node node);
extern char *timestamp(void);
