#include "so_stdio.h"

#include <sys/param.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <paths.h>

#define MAX_SIZE 4096

struct _so_file {
	int fd;
	int ptr_read;
	int ptr_write;
	int ff;
	int eof;
	int err;
	int type;
	int flag;
	long curr_pos;
	char *buff_read;
	char *buff_write;
};

extern char **environ;

void free_so(SO_FILE *stream)
{
	if (stream != NULL) {
		if (stream->ptr_read != 0) {
			// printf("DA?\n");
			free(stream->buff_read);
		}
		free(stream->buff_write);
		free(stream);
	}
}

SO_FILE *so_fopen(const char *pathname, const char *mode)
{
	SO_FILE *so_file = malloc(sizeof(SO_FILE));
	int fd;

	so_file->ptr_read = -1;
	so_file->ptr_write = 0;
	so_file->ff = 0;
	so_file->eof = 0;
	so_file->err = 0;
	so_file->type = 0;
	so_file->curr_pos = 0;
	so_file->flag = 0;
	so_file->buff_read = (char *) calloc(MAX_SIZE, sizeof(char));
	so_file->buff_write = (char *) calloc(MAX_SIZE, sizeof(char));
	if (so_file == NULL)
		return NULL;
	if (strcmp(mode, "r") == 0)
		so_file->fd = open(pathname, O_RDONLY);
	else if (strcmp(mode, "r+") == 0)
		so_file->fd = open(pathname, O_RDWR);
	else if (strcmp(mode, "w") == 0)
		so_file->fd = open(pathname, O_WRONLY | O_CREAT | O_TRUNC);
	else if (strcmp(mode, "w+") == 0)
		so_file->fd = open(pathname, O_RDWR | O_CREAT | O_TRUNC);
	else if (strcmp(mode, "a") == 0)
		so_file->fd = open(pathname, O_APPEND | O_WRONLY | O_CREAT);
	else if (strcmp(mode, "a+") == 0)
		so_file->fd = open(pathname, O_APPEND | O_RDWR | O_CREAT);
	else {
		free_so(so_file);
		return NULL;
	}

	if (so_file->fd < 0) {
		free_so(so_file);
		return NULL;
	}

	return so_file;
}

int so_fclose(SO_FILE *stream)
{
	if (stream->ptr_write != 0) {
		stream->ff = 1;
		int ret = so_fputc(-2, stream);

		if (ret == -1) {
			free_so(stream);
			return SO_EOF;
		}
	}
	int ret = close(stream->fd);

	if (ret == -1 || (stream->type == 1 && stream->err == 1)) {
		free_so(stream);
		return SO_EOF;
	}
	free_so(stream);
	return 0;
}

int so_fileno(SO_FILE *stream)
{
	return stream->fd;
}

int so_fgetc(SO_FILE *stream)
{
	int ch, l = 0;

	stream->ptr_read++;
	if (stream->ptr_read >= MAX_SIZE || stream->ptr_read == 0 || stream->curr_pos == stream->ptr_read) {
		int ret = read(stream->fd, stream->buff_read, MAX_SIZE);

		if (ret == -1) {
			stream->err = 1;
			return SO_EOF;
		}
		if (ret == 0) {
			stream->eof = 1;
			return SO_EOF;
		}
		if (ret < MAX_SIZE || stream->flag == 0) {
			stream->curr_pos += ret;
			if (ret < MAX_SIZE)
				stream->flag = 2;
			else
				stream->flag = 1;
		} else if (stream->flag == 1) {
			stream->flag = -1;
			stream->curr_pos++;
		}
		stream->ptr_read = 0;
		ch = (int)(stream->buff_read[stream->ptr_read]);
	} else {
		ch = (int)(stream->buff_read[stream->ptr_read]);
		if (stream->flag == -1)
			stream->curr_pos++;
	}
	stream->type = -1;
	return ch;
}

int so_fputc(int c, SO_FILE *stream)
{
	char ch = c;
	int ret;

	if (stream->ff || stream->ptr_write == MAX_SIZE) {
		ret = write(stream->fd, stream->buff_write, stream->ptr_write);
		if (ret == -1) {
			stream->err = 1;
			return SO_EOF;
		}
		free(stream->buff_write);
		stream->buff_write = (char *) calloc(MAX_SIZE, sizeof(char));
		if (c == -2) {
			stream->ptr_write = 0;
		} else {
			stream->buff_write[0] = ch;
			stream->ptr_write = 1;
		}
	} else {
		stream->buff_write[stream->ptr_write] = ch;
		stream->ptr_write++;
	}
	stream->type = 1;
	stream->curr_pos++;
	return c;
}

size_t so_fread(void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	int i, j, ret = 0;
	unsigned char *mem = (unsigned char *) ptr;

	for (i = 0; i < nmemb; i++) {
		ret++;
		for (j = 0; j < size; j++) {
			int res = so_fgetc(stream);

			if (res == -1 && stream->err == 1)
				return 0;
			unsigned char c = (unsigned char)res;

			mem[i * size + j] = c;
		}
	}
	stream->type = -1;
	if (ret <= nmemb)
		return ret;
	stream->err = 1;
	return 0;
}

size_t so_fwrite(const void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	int i, j, ret = 0;
	unsigned char *mem = (unsigned char *) ptr;

	for (i = 0; i < nmemb; i++) {
		ret++;
		for (j = 0; j < size; j++) {
			unsigned char b = mem[i*size + j];
			int res = so_fputc(b, stream);

			if (res == -1 || stream->err == 1)
				return 0;
		}
	}
	stream->type = 1;
	return ret;
}

int so_fflush(SO_FILE *stream)
{
	stream->ff = 1;
	size_t ret = so_fputc(-2, stream);

	if (ret == 0)
		return SO_EOF;
	return 0;
}

int so_feof(SO_FILE *stream)
{
	if (stream->eof == 1)
		return 1;
	return 0;
}

int so_ferror(SO_FILE *stream)
{
	if (stream->err == 1) {
		stream->ptr_read = 1;
		return 1;
	}
	return 0;
}

int so_fseek(SO_FILE *stream, long offset, int whence)
{
	if (stream->type == -1) { // read
		free(stream->buff_read);
		stream->buff_read = (char *) calloc(MAX_SIZE, sizeof(char));
		stream->ptr_read = -1;
	}
	if (stream->type == 1) { // write
		so_fputc(-2, stream);
	}
	int ret = lseek(stream->fd, offset, whence);

	if (ret < 0)
		return -1;

	stream->curr_pos = ret;
	return 0;
}

long so_ftell(SO_FILE *stream)
{
	long pos = stream->curr_pos;

	if (pos < 0)
		return -1;
	return pos;
}

SO_FILE *so_popen(const char *command, const char *type)
{
	return NULL;
}

int so_pclose(SO_FILE *stream)
{
	return 0;
}
