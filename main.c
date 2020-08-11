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
#include <stdlib.h>		/* exit() */
#include <stdio.h>		/* printf() etc. */
#include <unistd.h>		/* unlink() */
#include <sys/stat.h>		/* S_IRUSR, S_IWUSR, S_IRGRP, S_IROTH */
#include <fcntl.h>		/* open() */
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <poll.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#ifndef UNIX_PATH_MAX
# define UNIX_PATH_MAX 108
#endif

#include "mktorrent.h"

/* global variables */

FILE *debug_stream = NULL;
char *logfile = NULL;

/* options */
size_t piece_length = 18;	/* 2^18 = 256kb by default */
char *announce_url = NULL;	/* announce url */
char *torrent_name = NULL;	/* name of the torrent (name of directory) */
char *metainfo_file_path;	/* absolute path to the metainfo file */
char *comment = NULL;		/* optional comment to add to the metainfo */
char *directory_name = NULL;
int target_is_directory = 0;	/* target is a directory not just a single file */
int no_creation_date = 0;	/* don't write the creation date */
int private = 0;		/* set the private flag */
int verbose = 0;		/* be verbose */
int partial = 0;
int finish = 0;
int remove_op = 0;
int daemon_start = 0;

int mktd_loglevel = MKTD_INFO; 

/* information calculated by read_dir() */
unsigned long long torrent_size = 0;	/* the combined size of all files in the torrent */
fl_node file_list = NULL;	/* linked list of files and their individual sizes */
unsigned int pieces;		/* number of pieces */

/* init.c */
extern void init(int argc, char *argv[]);

/* hash.c */
extern unsigned char *make_hash();

/* output.c */
extern void write_metainfo(FILE * file, unsigned char *hash_string);

void MKTD_LOG_dump_node(fl_node node)
{
	MKTD_LOG(MKTD_DEBUG, "text dump of %s's node:\n", node->path);
	MKTD_LOG(MKTD_DEBUG, "	size: %llu\n", (unsigned long long)node->size);
	MKTD_LOG(MKTD_DEBUG, "	offset: %llu\n", (unsigned long long)node->hashed);
	MKTD_LOG(MKTD_DEBUG, "	pending: %d\n", node->pending);
}

/*
 * create and open the metainfo file for writing and create a stream for it
 * we don't want to overwrite anything, so abort if the file is already there
 */
static FILE *open_file()
{
	int fd;			/* file descriptor */
	FILE *stream;		/* file stream */

	/* open and create the file if it doesn't exist already */
	if ((fd = open(metainfo_file_path, O_WRONLY | O_CREAT | O_EXCL,
		       S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
		fprintf(stderr, "error: couldn't create %s for writing, "
			"perhaps it is already there.\n",
			metainfo_file_path);
		exit(EXIT_FAILURE);
	}

	/* create the stream from this filedescriptor */
	if ((stream = fdopen(fd, "w")) == NULL) {
		fprintf(stderr,
			"error: couldn't create stream for file %s.",
			metainfo_file_path);
		exit(EXIT_FAILURE);
	}

	return stream;
}

/*
 * close the metainfo file
 */
static void close_file(FILE * file)
{
	/* close the metainfo file */
	if (fclose(file)) {
		fprintf(stderr, "error: couldn't close stream.");
		exit(EXIT_FAILURE);
	}
}

static char *unix_sock_name(char *basestr)
{
	size_t n = strlen(basestr) + sizeof(".un");
	char *name;

	name = xmalloc(n);
	sprintf(name, "%s.un", basestr);
	return name;
}

struct session
{
	int	is_client;
	char 	*sk_path;
	int	sk_filedes;
} *session;

struct session *init_session(void)
{
	struct session *s;

	s = xmalloc(sizeof(*s));
	s->sk_path = NULL;
	s->sk_filedes = -1;
	s->is_client = 0;
	return s;
}

void init_socket(void)
{
	struct sockaddr_un addr;
	char *sun_path = unix_sock_name(torrent_name);
	int sk, err;
	
	session = init_session();
	sk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sk == -1)
		error_exit(1, "socket()");
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	sprintf(&addr.sun_path[1], "%s", sun_path);
	err = bind(sk, (struct sockaddr *)&addr, sizeof(addr));
	if (err) {
		if (errno != EADDRINUSE)
			error_exit(1, "bind()");
		session->is_client = 1;
	} else 
		listen(sk, 64);
	session->sk_filedes = sk;
	session->sk_path = sun_path;
}

int is_client(void)
{
	return session->is_client;
}

typedef enum mktd_message_e 
{
	MKT_PARTIAL,
	MKT_FINISH,
	MKT_REMOVE,
	MKT_ACK,
	MKT_ERROR,
} mktd_command_t;

#define MKT_MAX_PATH 128
struct mktorrentd_op
{
	mktd_command_t	op_command;
	char 		op_path[MKT_MAX_PATH];
};

static char *op_string(mktd_command_t op)
{
	static char *map[] = {
		"--partial", "--finish",
		"--remove", "--ack",
	};
	return map[op];
}

static int op_valid(mktd_command_t op)
{
	if (op < 0)
		return 0;
	if (op > MKT_ERROR)
		return 0;
	return 1;
}

char *timestamp(void)
{
	struct tm *tmp;
	time_t tstamp;
	static char buf[200], *fmt = "%D/%T";

	tstamp = time(NULL);
	tmp = localtime(&tstamp);
	strftime(buf, sizeof(buf), fmt, tmp);
	return buf;
}

static void send_message(int fd, struct mktorrentd_op *op)
{
	int err;

	MKTD_LOG(MKTD_DEBUG, "op->op_command:%s (%d)\n", 
			op_string(op->op_command), op->op_command);
	MKTD_LOG(MKTD_DEBUG, "op->op_path:%s\n", 
			op->op_path[0] == 0 ? "(null)" : op->op_path);
	//err = sendto(fd, op, sizeof(*op), 0, (struct sockaddr *)to, sizeof(*to));
	err = write(fd, op, sizeof(*op));
	if (err == -1)
		error_exit(1, "write()");
}

static void recv_message(int fd, struct mktorrentd_op *op)
{
	int err;
	struct tm *tmp;
	time_t tstamp;
	char buf[200], *fmt = "%D/%T";

	tstamp = time(NULL);
	tmp = localtime(&tstamp);
	strftime(buf, sizeof(buf), fmt, tmp);

	err = read(fd, op, sizeof(*op));
	if (err == -1)
		error_exit(1, "read(socket)");
	MKTD_LOG(MKTD_INFO, "(%s): Recived request: %s ", buf, op_string(op->op_command));
	MKTD_LOG(MKTD_INFO, "path: %s\n", op->op_path[0] != 0 ? 
			op->op_path : "(null)");
}

static void daemonize(void)
{
	extern char *logfile;

	if (fork() != 0) /* parent */
		_exit(EXIT_SUCCESS);
	debug_stream = fopen(logfile, "a+");
	if (!debug_stream)
		error_exit(1, "couldn't open log file");
}	

#define SECS_TO_MILI(secs) ((secs) * 1000)
#define MINUTES_TO_SECS(mins) ((mins) * 60)

#define DAEMON_TIMEOUT_SECONDS MINUTES_TO_SECS(25)
#define DAEMON_TIMEOUT_MILISECONDS SECS_TO_MILI(DAEMON_TIMEOUT_SECONDS)

#define CLIENT_TIMEOUT_SECONDS MINUTES_TO_SECS(25)
#define CLIENT_TIMEOUT_MILISECONDS SECS_TO_MILI(CLIENT_TIMEOUT_SECONDS)

static int wait_timeout(int sk, int timeout)
{
	struct pollfd pfd = { 
		.fd = sk,  
		.events = POLLIN,
	};
	int err;
	
	err = poll(&pfd, 1, timeout);
	if (err == -1)
		error_exit(1, "poll()\n");
	return err > 0;
}

#if 1
static unsigned long long get_queued_bytes(void)
{
	fl_node it;
	unsigned long long ret = 0;
	
	lock_flist();
	for (it = file_list; it != NULL; it = it->next)
		if (it->pending == 1)
			ret += it->size - it->hashed;
	unlock_flist();
	return ret;
}
#endif

static fl_node flnode_new(char *n_path)
{
	fl_node n;
	struct stat st;
	int fd;

	n = xmalloc(sizeof(struct fl_node_s));
	n->hashed = 0;
	n->next = NULL;
	n->path = strdup(n_path);
	n->pending = 1;
	fd = open(n_path, O_RDONLY);
	if (fd == -1) {
		MKTD_LOG(MKTD_INFO, "ERROR: open(%s)", n_path);
		exit(EXIT_FAILURE);
	}

	fsync(fd);

	if (fstat(fd, &st) == -1) {
		fprintf(stderr, "%s ", n_path);
		error_exit(1, "stat()");
	}
	close(fd);
	n->size = st.st_size;
	return n;
}

static void flnode_add(fl_node n)
{
	fl_node *pos;
	
	pos = &file_list;
	while (*pos)
		pos = &((*pos)->next);
	n->next = *pos;
	*pos = n;
}

static void flnode_del(fl_node n, fl_node prev)
{
	MKTD_LOG(MKTD_DEBUG, "deleting node %s\n", n->path);
	if (prev)
		prev->next = n->next;
	else
		file_list = n->next;
	free(n->path);
	free(n);
}

int flnode_open(fl_node node, int flags)
{
	int fd;
	off_t ret;
	
	MKTD_LOG(MKTD_DEBUG, "%s: trying to open:%s\n",
			__func__, node->path);
	fd = open(node->path, flags);
	if (fd == -1)
		return -1;
	MKTD_LOG(MKTD_DEBUG, "opened\n");
	MKTD_LOG(MKTD_DEBUG, "fd: %d, hashed: %llu\n", fd, (unsigned long long)node->hashed);
	ret = lseek(fd, node->hashed, SEEK_SET);
	if (ret == (off_t)-1) {
		close(fd);
		return -1;
	}
	return fd;
}

static int nr_blocks(unsigned long long size)
{
	return size / piece_length;
}

static int flnode_exists(char *path)
{
	fl_node it;

	for (it = file_list; it != NULL; it = it->next)
		if (strcmp(it->path, path) == 0)
			return 1;
	return 0;
}

unsigned long long queued_bytes = 0;
unsigned long long total_bytes = 0;

static void handle_request(struct mktorrentd_op *r)
{
	switch (r->op_command) {
	case MKT_FINISH: 
	{
		int blocks;
		finish = 1;

		blocks = (queued_bytes + piece_length - 1) / piece_length;
		if (blocks > 0)
			hash_blocks(blocks, 1);
		break;
	}
	case MKT_PARTIAL:
	{
		int blocks;
		fl_node n;
		if (flnode_exists(r->op_path)) {
			MKTD_LOG(MKTD_INFO, "(%s): duplicated file %s, ignoring it ...\n",
					timestamp(), r->op_path);
			return;
		}
		n = flnode_new(r->op_path);
		flnode_add(n);
		blocks = nr_blocks(queued_bytes + n->size);
		if (blocks || finish) {
			MKTD_LOG(MKTD_DEBUG, "hashing %d blocks\n", blocks);
			if (finish && ((queued_bytes + n->size) % piece_length) != 0) {
				blocks++;
				queued_bytes = (n->size + queued_bytes) % piece_length;
				hash_blocks(blocks, 1);
			} else if (blocks)
				hash_blocks(blocks, 0);
		}
		queued_bytes = get_queued_bytes();
		MKTD_LOG(MKTD_DEBUG, "queued bytes: %llu\n", queued_bytes);
		MKTD_LOG_dump_node(n);
		break;
	}
	case MKT_REMOVE:
	{
		char *target = r->op_path;
		fl_node n_it, last_piece = NULL;
		int bytes = 0;
		unsigned long long size = 0, last_offset = 0;
		unsigned int blocks = 0;
		
		for (n_it = file_list; n_it != NULL; n_it = n_it->next) {
			if (!strcmp(n_it->path, target))
				break;
			bytes += n_it->size;
			if (bytes >= piece_length) {
				last_piece = n_it; /* last completed */
				blocks += nr_blocks(bytes);
				bytes = bytes % piece_length;
				if (bytes != 0)
					last_offset = n_it->size - bytes;
				else
					last_offset = 0;
			}
		}

		MKTD_LOG(MKTD_DEBUG, "bytes: 	%d\n", bytes);
		MKTD_LOG(MKTD_DEBUG, "last_offst: 	%llu\n", last_offset);
		MKTD_LOG(MKTD_DEBUG, "blocks 	%d\n", blocks);
		if (last_piece)
			MKTD_LOG(MKTD_DEBUG, "last_piece: 	%s\n", last_piece->path);

		if (!n_it) {
			MKTD_LOG(MKTD_DEBUG, "Warning: Asked to remove "
				"unexistant path \"%s\"\n", target);
			return;
		}
			
		if (last_piece) {
			if (last_offset != 0) {
				last_piece->hashed = last_offset;
				last_piece->pending = 1;
				size = last_piece->size - last_offset;
			}
			unhash_from(blocks);
		}
		
		fl_node tmp = n_it->next;
		flnode_del(n_it, last_piece);
		n_it = tmp;
		for (; n_it != NULL; n_it = n_it->next) {
			n_it->hashed = 0;
			n_it->pending = 1;
			size += n_it->size;
		}
		MKTD_LOG(MKTD_DEBUG, "size: %llu\n", size);
		blocks = nr_blocks(size);
		MKTD_LOG(MKTD_DEBUG, "blocks: %d\n", blocks);
		if (blocks > 0) {
			MKTD_LOG(MKTD_DEBUG, "rehasing %d blocks\n", blocks);
			hash_blocks(blocks, 0);
			size = size % piece_length;
		}
		MKTD_LOG(MKTD_DEBUG, "new queued_bytes: %llu\n", size);
		queued_bytes = size;
		break;
	}
	default: assert(0);
	}
}

static int client_sk = -1;

static struct mktorrentd_op *get_request(void)
{
	struct mktorrentd_op *op;
	struct sockaddr_un from;
	unsigned int alen = sizeof(from);

	if (!wait_timeout(session->sk_filedes, DAEMON_TIMEOUT_MILISECONDS))
		return NULL;
	client_sk = accept(session->sk_filedes, (struct sockaddr *)&from, &alen);
	if (client_sk == -1)
		error_exit(1, "accept()");
	op = xmalloc(sizeof(*op));
	recv_message(client_sk, op);
	if (!op_valid(op->op_command)) 
		MKTD_LOG(MKTD_DEBUG, "error: unknown command recived from the client\n");
	return op;
}

static void do_daemon(void)
{
	//struct mktorrentd_op init;
	int done = 0;
	
	if (!daemon_start) {
		MKTD_LOG(MKTD_INFO, "(%s): ERROR: daemonizing before issuing start for %s",
				timestamp(), directory_name);
		exit(EXIT_FAILURE);
	}

	if (chdir(directory_name)) {
		fprintf(stderr, "cannot change dir to %s\n",
				directory_name);
		exit(EXIT_FAILURE);
	}
	daemonize();
#if 0
	/* hand crafted daemon initial request */
	init.op_command = MKT_PARTIAL;
	sprintf(init.op_path, "%s", file_list->path);
	MKTD_LOG(MKTD_INFO, "(%s) initial request: %s\n", timestamp(), file_list->path);
	handle_request(&init);
#endif
	MKTD_LOG(MKTD_INFO, "(%s): starting daemon for %s\n",
			timestamp(), directory_name);
	while (!done) {
		struct mktorrentd_op *req;

		req = get_request();
		if (!req) /* timedout */
			break;
		if (req->op_command == MKT_FINISH)
			done = 1;
		handle_request(req);
		free(req);
		close(client_sk);
		client_sk = -1;
	}
	if (!done) {
		MKTD_LOG(MKTD_INFO, "(%s): daemon timed out after %d seconds\n",
				timestamp(), DAEMON_TIMEOUT_SECONDS);
		exit(1);
	}
	close(session->sk_filedes);
}

static int do_client(void)
{
	struct mktorrentd_op op;
	struct sockaddr_un addr;
	int err;

	if (finish)
		op.op_command = MKT_FINISH;
	else if (remove_op)
		op.op_command = MKT_REMOVE;
	else
		op.op_command = MKT_PARTIAL;

	if (finish)
		sprintf(op.op_path, "%s", directory_name);
	else
		sprintf(op.op_path, "%s", file_list->path);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	sprintf(&addr.sun_path[1], "%s", session->sk_path);
	err = connect(session->sk_filedes, (struct sockaddr *)&addr, sizeof(addr));
	if (err == -1)
		error_exit(1, "connect()");
	send_message(session->sk_filedes, &op);
	mktd_command_t msg = -1;
	if (!wait_timeout(session->sk_filedes, CLIENT_TIMEOUT_MILISECONDS)) {
		fprintf(stderr, "client timeout after %d seconds\n", CLIENT_TIMEOUT_SECONDS);
		exit(1);
	}
	err = read(session->sk_filedes, &msg, sizeof(msg));
	if (err == -1)
		error_exit(1, "read(sock)\n");
	close(session->sk_filedes);
	return 0;
}

/*
 * main().. it starts
 */
int main(int argc, char *argv[])
{
	static FILE *file;	/* stream for writing to the metainfo file */

	/* print who we are */
	printf("mktorrent " VERSION " (c) 2007 Emil Renner Berthing\n\n");

	/* process options and initiate global variables */
	init(argc, argv);
	if (partial) {
		init_socket();
		if (is_client())
			return do_client();
		do_daemon();
	}
	/* open the file stream now, so we don't have to abort
	   _after_ we did all the hashing in case we fail */
	file = open_file();

	/* calculate hash string and write the metainfo to file */
	write_metainfo(file, final_hash());

	/* close the file stream */
	close_file(file);

	/* yeih! everything seemed to go as planned */
	return EXIT_SUCCESS;
}
