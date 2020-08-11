/*
This file is part of mktorrent
Copyright (C) 2007  Emil Renner Berthing

mktorrent is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

mktorrent is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
*/
#include <stdlib.h>		/* exit(), malloc() */
#include <stdio.h>		/* printf() etc. */
#include <string.h>
#include <fcntl.h>		/* open() */
#include <unistd.h>		/* access(), read(), close() */
#include <openssl/sha.h>	/* SHA1() - remember to compile with -lssl */
#include <pthread.h>		/* pthread functions and data structures */
#include <sys/types.h>

#include "list.h"
#include "mktorrent.h"

#ifndef PROGRESS_PERIOD
#define PROGRESS_PERIOD 200000
#endif

static unsigned int pieces_done = 0;	/* pieces processed so far */
/* piece to be transferred between threads */
static unsigned char *transfer_piece;
/* mutex only unlocked when transfer_piece contains a newly read piece */
static pthread_mutex_t data_ready_mutex = PTHREAD_MUTEX_INITIALIZER;
/* only unlocked when transfer_piece contains a piece already hashed */
static pthread_mutex_t free_space_mutex = PTHREAD_MUTEX_INITIALIZER;

struct hash_item 
{
	unsigned char *hash_piece;
	struct list_head link;
};

static LIST_HEAD(hash_list);

unsigned int hash_items_count = 0;

static pthread_mutex_t fl_list_lock = PTHREAD_MUTEX_INITIALIZER;

void lock_flist(void)
{
	pthread_mutex_lock(&fl_list_lock);
}

void unlock_flist(void)
{
	pthread_mutex_unlock(&fl_list_lock);
}

static struct hash_item *hash_item_new(int piece_length)
{
	struct hash_item *new_it;

	new_it = xmalloc(sizeof(*new_it));
	new_it->hash_piece = xmalloc(piece_length);
	INIT_LIST_HEAD(&new_it->link);
	MKTD_LOG(MKTD_DEBUG, "Adding item: %p\n", new_it->hash_piece);
	return new_it;
}

/*
 * deliver a free piece buffer and return a new piece to be hashed
 * thread safe
 */
static unsigned char *get_piece(unsigned char *free_buffer)
{
	unsigned char *buf;

	pthread_mutex_lock(&data_ready_mutex);
	buf = transfer_piece;
	transfer_piece = free_buffer;
	pthread_mutex_unlock(&free_space_mutex);
	return buf;
}

/*
 * deliver a newly read piece to be hashed and return a free piece buffer
 * thread safe
 */
static unsigned char *deliver_piece(unsigned char *piece)
{
	unsigned char *buf;

	pthread_mutex_lock(&free_space_mutex);
	buf = transfer_piece;
	transfer_piece = piece;
	pthread_mutex_unlock(&data_ready_mutex);
	return buf;
}

#if 0
/*
 * print the progress in a thread of its own
 */
static void *print_progress(void *data)
{
	while (1) {
		/* print progress and flush the buffer immediately */
		printf("\rHashed %u/%u pieces.", pieces_done, pieces);
		fflush(stdout);
		/* now sleep for PROGRESS_PERIOD micro seconds */
		usleep(PROGRESS_PERIOD);
	}
	return NULL;
}
#endif

static void fl_node_update(int fd, fl_node n)
{
	off_t ret;

	ret = lseek(fd, 0, SEEK_CUR);
	if (ret == (off_t)-1)
		error_exit(1, "lseek()");
	n->pending = ret != n->size;
	n->hashed = ret;
	MKTD_LOG(MKTD_DEBUG, "updating %s\n", n->path);
	MKTD_LOG(MKTD_DEBUG, "	pending: %d\n", n->pending);
	MKTD_LOG(MKTD_DEBUG, "	hashed:  %llu\n", (unsigned long long)n->hashed);
}

/*
 * this thread goes through all the files in the torrent, reads their
 * content in pieces of piece_length and deliver them to the hashing thread
 */
static void *file_reader(void *data)
{
	/* current piece buffer to fill with data from files */
	unsigned char *piece = (unsigned char *) data;
	fl_node p;		/* pointer to a place in the file list */
	int fd;			/* file descriptor */
	ssize_t r = 0;		/* number of bytes read from file(s) into
				   the current piece buffer */
	int done = 0, nr = pieces;
#ifndef NO_HASH_CHECK
	unsigned long long counter = 0;	/* number of bytes hashed
					   should match size when done */
#endif
	lock_flist();
	/* go through all the files in the file list */
	for (p = file_list; p; p = p->next) {
		
		if (partial && !p->pending)
			continue;

		/* open the current file for reading */
		if ((fd = flnode_open(p, O_RDONLY)) == -1) 
			error_exit(1, "open()");
		/* fill the buffer with the contents of the file and deliver
		   it to the hashing thread.
		   repeat until we can't fill the buffer and we've thus come
		   to the end of the file */
		while ((r += read(fd, piece + r, piece_length - r))
		       == piece_length) {
			/* deliver the piece and get a new empty buffer */
			piece = deliver_piece(piece);
#ifndef NO_HASH_CHECK
			/* count the number of bytes read from files */
			counter += r;	/* r == piece_length */
#endif
			/* buffer is now empty and we can start
			   filling it again */
			r = 0;
			done++;
			if (partial && done == nr && !finish)
				break;
		}
		if (partial)
			fl_node_update(fd, p);
		/* now close the file */
		if (close(fd)) {
			fprintf(stderr, "error: failed to close %s.",
				p->path);
			exit(EXIT_FAILURE);
		}
		if (partial && !finish && done == nr)
			break;
	}

	/* deliver the last irregular sized piece, if there is one */
	if (r != 0) {
		MKTD_LOG(MKTD_DEBUG, "delivering irregular %zu bytes\n", r);
		deliver_piece(piece);
	}
#ifndef NO_HASH_CHECK
	/* now add the last number of read bytes and check if the
	   number of bytes read from files matches size */
	counter += r;
	if (0 && counter != torrent_size) {
		fprintf(stderr, "error: counted %llu bytes, "
			"but hashed %llu bytes.\n", torrent_size, counter);
		exit(EXIT_FAILURE);
	}
#endif
	unlock_flist();
	return NULL;
}

/*
 * allocate memory for the hash string and buffers,
 * initiate the progress printer and file reader threads then
 * then start hashing the pieces delivered by the file reader thread.
 * the SHA1 hash of every piece is concatenated into the hash string.
 * last piece may be shorter
 */
unsigned char *make_hash()
{

	unsigned char *hash_string = NULL,	/* the hash string we're producing */
	*pos = NULL,			/* where in hash_string to put the
				   hash of the next piece */
	*piece,			/* the current piece we're hashing */
	*piece1, *piece2, *piece3;	/* allocated piece buffers */
	//pthread_t print_progress_thread;	/* progress printer thread */
	pthread_t file_reader_thread;	/* file reader thread */
	unsigned long last_piece_length;	/* length of last piece */


	/* allocate memory for the hash string and set pos to point
	   to its beginning.
	   every SHA1 hash is SHA_DIGEST_LENGTH (20) bytes long */
	if (!partial)
		pos = hash_string = malloc(pieces * SHA_DIGEST_LENGTH);
	/* allocate memory for 3 pieces */
	piece1 = malloc(piece_length);
	piece2 = malloc(piece_length);
	piece3 = malloc(piece_length);

	/* the data_ready_mutex should be locked initially as there are
	   no new pieces read yet */
	pthread_mutex_lock(&data_ready_mutex);
	/* let the first piece buffer be in transfer initially */
	transfer_piece = piece1;
	/* give the second piece buffer to the file reader thread and
	   set it to work */
	pthread_create(&file_reader_thread, NULL, file_reader, piece2);
	/* we set piece to the third piece for the while loop to begin */
	piece = piece3;

	/* now set off the progress printer */
	//pthread_create(&print_progress_thread, NULL, print_progress, NULL);

	/* repeat hashing until only the last piece remains */
	while (pieces_done < pieces - 1) {
		/* deliver the already hashed piece and get a newly read one */
		piece = get_piece(piece);
		/* calculate the SHA1 hash of the piece and write it
		   the right place in the hash string */
		if (!partial) {
			SHA1(piece, piece_length, pos);
			/* next hash should be written 20 bytes further ahead */
			pos += SHA_DIGEST_LENGTH;
		} else {
			struct hash_item *it;

			it = hash_item_new(piece_length);
			SHA1(piece, piece_length, it->hash_piece);
			list_add_tail(&it->link, &hash_list);
			hash_items_count++;
		}
		/* yeih! one piece done */
		pieces_done++;
	}

	/* get the last piece */
	piece = get_piece(piece);
	/* calculate the size of the last piece */
	last_piece_length = torrent_size % piece_length;
	if (last_piece_length == 0)
		last_piece_length = piece_length;
	if (!partial) {
		/* now write its hash to the hash string */
		SHA1(piece, last_piece_length, pos);
	} else {
		struct hash_item *it;

		it = hash_item_new(piece_length);
		SHA1(piece, last_piece_length, it->hash_piece);
		list_add_tail(&it->link, &hash_list);
		hash_items_count++;
	}
	MKTD_LOG(MKTD_DEBUG, "expecting %d pieces, done: %d\n", pieces, pieces_done +1);
	/* yeih! we're done */
	pieces_done++;
	/* ..so stop printing our progress. */
	//pthread_cancel(print_progress_thread);
	/* ok, let the user know we're done too */
	if (!partial)
		printf("\rHashed %u/%u pieces.\n", pieces_done, pieces);

	/* the file reader thread stops itself when it's done. */

	/* free the piece buffers before we return */
	free(piece1);
	free(piece2);
	free(piece3);
	pthread_mutex_unlock(&data_ready_mutex);
	/* return our shiny new hash string */
	return hash_string;
}

void hash_blocks(int nr, int flush)
{
	/* from main.c::handle_request() */
	extern unsigned long long queued_bytes;

	pieces_done = 0;
	pieces = nr;
	if (flush)
		torrent_size = queued_bytes;
	else
		torrent_size = nr * piece_length;
	make_hash();
}

void hash_item_del(struct hash_item *item)
{
	MKTD_LOG(MKTD_DEBUG, "Deleting item %p\n", item->hash_piece);
	list_del(&item->link);
	free(item->hash_piece);
	free(item);
	hash_items_count--;
	MKTD_LOG(MKTD_DEBUG, "currently %d pieces\n", hash_items_count);
}

void unhash_from(int blknr)
{
	struct hash_item *i, *tmp;
	int c = 0;
	
	MKTD_LOG(MKTD_DEBUG, "deleting %d blocks\n", blknr);
	list_for_each_entry_safe(i, tmp, &hash_list, link) {
		if ((c + 1) > blknr)
			hash_item_del(i);
		c++;
	}
}

static void *sha_alloc(void)
{
	return xmalloc(hash_items_count * SHA_DIGEST_LENGTH);
}

static unsigned char *__final_hash(void)
{
	unsigned char *sha_digest = sha_alloc();
	unsigned char *p = sha_digest;
	struct hash_item *it;

	list_for_each_entry(it, &hash_list, link) {
		memcpy(p, it->hash_piece, SHA_DIGEST_LENGTH);
		p += SHA_DIGEST_LENGTH;
	}
	pieces = hash_items_count;
	MKTD_LOG(MKTD_INFO, "(%s): finally hashed %d pieces\n",
			timestamp(), pieces);
	return sha_digest;
}

unsigned char *final_hash(void)
{
	if (finish)
		return __final_hash();
	return make_hash();
}
