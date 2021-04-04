#include "so_stdio.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_SIZE 4096

struct _so_file {
	HANDLE fd;
	DWORD ptr_read;
	DWORD ptr_write;
	DWORD ff;
	DWORD eof;
	DWORD err;
	DWORD type;
	DWORD flag;
	LONG curr_pos;
	CHAR *buff_read;
	CHAR *buff_write;
};

void free_so(SO_FILE *stream)
{
	if (stream != NULL) {
		if (stream->ptr_read != 0) {
			free(stream->buff_read);
		}
		free(stream->buff_write);
		free(stream);
	}
}

SO_FILE *so_fopen(const char *pathname, const char *mode)
{
	SO_FILE *so_file = malloc(sizeof(SO_FILE));

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
		so_file->fd = CreateFile(pathname,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
	else if (strcmp(mode, "r+") == 0)
		so_file->fd = CreateFile(pathname,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
	else if (strcmp(mode, "w") == 0)
		so_file->fd = CreateFile(pathname,
			GENERIC_WRITE,
			FILE_SHARE_WRITE,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
	else if (strcmp(mode, "w+") == 0)
		so_file->fd = CreateFile(pathname,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_ALWAYS | TRUNCATE_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
	else if (strcmp(mode, "a") == 0)
		so_file->fd = CreateFile(pathname,
			FILE_APPEND_DATA,
			FILE_SHARE_WRITE,
			NULL,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
	else if (strcmp(mode, "a+") == 0)
		so_file->fd = CreateFile(pathname,
			FILE_APPEND_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
	else {
		free_so(so_file);
		return NULL;
	}

	if (so_file->fd == INVALID_HANDLE_VALUE) {
		free_so(so_file);
		return NULL;
	}

	return so_file;
}

int so_fclose(SO_FILE *stream)
{
	BOOL ret;
	DWORD res;

	if (stream->ptr_write != 0) {
		stream->ff = 1;
		res = so_fputc(-2, stream);

		if (res == -1) {
			free_so(stream);
			return SO_EOF;
		}
	}
	ret = CloseHandle(stream->fd);
	if (ret == FALSE || (stream->type == 1 && stream->err == 1)) {
		free_so(stream);
		return SO_EOF;
	}
	free_so(stream);
	return 0;
}

HANDLE so_fileno(SO_FILE *stream)
{
	return stream->fd;
}

int so_fgetc(SO_FILE *stream)
{
	DWORD ch, l = 0;
	BOOL ret;
	DWORD bytesRead = 0;

	stream->ptr_read++;
	if (stream->ptr_read >= MAX_SIZE
	|| stream->ptr_read == 0
	|| stream->curr_pos == stream->ptr_read) {
		ret = ReadFile(stream->fd,
			stream->buff_read,
			MAX_SIZE,
			&bytesRead,
			NULL);

		if (ret == FALSE) {
			stream->err = 1;
			return SO_EOF;
		}
		if (bytesRead == 0) {
			stream->eof = 1;
			return SO_EOF;
		}
		if (bytesRead < MAX_SIZE || stream->flag == 0) {
			stream->curr_pos += bytesRead;
			if (bytesRead < MAX_SIZE)
				stream->flag = 2;
			else
				stream->flag = 1;
		} else if (stream->flag == 1) {
			stream->flag = -1;
			stream->curr_pos++;
		}
		stream->ptr_read = 0;
		ch = (DWORD)(stream->buff_read[stream->ptr_read]);
	} else {
		ch = (DWORD)(stream->buff_read[stream->ptr_read]);
		if (stream->flag == -1)
			stream->curr_pos++;
	}
	stream->type = -1;
	return ch;
}

int so_fputc(int c, SO_FILE *stream)
{
	CHAR ch = c;
	DWORD bytesWritten = 0;
	BOOL ret;

	if (stream->ff || stream->ptr_write == MAX_SIZE) {
		ret = WriteFile(stream->fd,
			stream->buff_write,
			stream->ptr_write,
			&bytesWritten,
			NULL);
		if (ret == FALSE) {
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
	DWORD i, j, ret = 0, res;
	BYTE c;
	BYTE *mem = (BYTE *) ptr;

	for (i = 0; i < nmemb; i++) {
		ret++;
		for (j = 0; j < size; j++) {
			res = so_fgetc(stream);

			if (res == -1 && stream->err == 1)
				return 0;
			c = (BYTE)res;

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
	DWORD i, j, ret = 0, res;
	BYTE *mem = (BYTE *) ptr;
	BYTE b;

	for (i = 0; i < nmemb; i++) {
		ret++;
		for (j = 0; j < size; j++) {
			b = mem[i*size + j];
			res = so_fputc(b, stream);

			if (res == -1 || stream->err == 1)
				return 0;
		}
	}
	stream->type = 1;
	return ret;
}

int so_fflush(SO_FILE *stream)
{
	DWORD ret;

	stream->ff = 1;
	ret = so_fputc(-2, stream);
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
	LONG ret;

	if (stream->type == -1) { // read
		free(stream->buff_read);
		stream->buff_read = (char *) calloc(MAX_SIZE, sizeof(char));
		stream->ptr_read = -1;
	}
	if (stream->type == 1) { // write
		so_fputc(-2, stream);
	}
	ret = SetFilePointer(stream->fd,
		offset,
		NULL,
		whence);
	if (ret == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
		return -1;

	stream->curr_pos = ret;
	return 0;
}

long so_ftell(SO_FILE *stream)
{
	LONG pos = stream->curr_pos;

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
