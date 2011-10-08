/***************************************************************************
 * Copyright (C) 2011 by Robert G. Jakabosky <bobby@sharedrealm.com>       *
 *                                                                         *
 ***************************************************************************/
#ifndef BUFFER_POOL_H
#define BUFFER_POOL_H

#include <sys/queue.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

typedef uint16_t buflen_t;

#define BUFFER_UNITS 16
#define BUFFER_OVERHEAD (sizeof(Buffer))

#define BUFFER_MAX_LENGTH (((1<< (sizeof(buflen_t) * 8)) - 1) - BUFFER_OVERHEAD)
#define BUFFER_FREE_MARK ((1<< (sizeof(buflen_t) * 8)) - 1)

#define BUFFER_VALID(buf) assert((((ptrdiff_t)(buf)) & (BUFFER_UNITS - 1)) == 0)

typedef struct Buffer Buffer;

typedef struct BufferPool BufferPool;

/**
 * Buffer in pool block.
 */
struct Buffer {
	STAILQ_ENTRY(Buffer) bufs;
	/* read-only. */
	buflen_t block;  /**< units offset from start of buffer pool block. */
	buflen_t size;   /**< size in buffer units. */
	buflen_t len;    /**< length of data in bytes. */
	/* read/write */
	uint8_t  data[];
};

static inline int buffer_is_free(Buffer *buf) {
	BUFFER_VALID(buf);
	return (buf->len == BUFFER_FREE_MARK) ? 1 : 0;
}

static inline int buffer_is_last_buffer(Buffer *buf) {
	BUFFER_VALID(buf);
	return (buf->size == 0) ? 1 : 0;
}

static inline uint32_t buffer_length(Buffer *buf) {
	BUFFER_VALID(buf);
	return buf->len;
}

static inline uint32_t buffer_size(Buffer *buf) {
	BUFFER_VALID(buf);
	return (buf->size * BUFFER_UNITS) - BUFFER_OVERHEAD;
}

static inline uint8_t *buffer_data(Buffer *buf) {
	BUFFER_VALID(buf);
	return &(buf->data[0]);
}

void buffer_set_length(Buffer *buf, uint32_t len);

BufferPool *buffer_get_pool(Buffer *buf);

void buffer_free(Buffer *buf);

/*
 * Buffer pool
 */
BufferPool *bufferpool_new_full(size_t min_free, size_t max_free);
#define bufferpool_new() bufferpool_new_full(0,0)

void bufferpool_free(BufferPool *pool);

Buffer *bufferpool_get_buffer(BufferPool *pool, uint32_t min_len);

void bufferpool_print_stats(BufferPool *pool);

#endif /* BUFFER_POOL_H */
