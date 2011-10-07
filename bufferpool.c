/***************************************************************************
 * Copyright (C) 2011 by Robert G. Jakabosky <bobby@sharedrealm.com>       *
 *                                                                         *
 ***************************************************************************/

#include "bufferpool.h"

#include <stdlib.h>
#include <string.h>

#define BUFFER_UNITS_LEN(len) (((len) + (BUFFER_UNITS-1)) / BUFFER_UNITS)
#define BUFFER_MIN_SIZE (BUFFER_UNITS * 16)
#define BUFFER_MAX_SIZE ((1<< (sizeof(buflen_t) * 8)) - 1)

#define BUFFER_OFFSET_ADD(buf, off) (((uint8_t *)(buf)) + ((off) * BUFFER_UNITS))
#define BUFFER_OFFSET_SUB(buf, off) (((uint8_t *)(buf)) - ((off) * BUFFER_UNITS))

typedef struct BufferPoolBlock BufferPoolBlock;

static void bufferpool_free_block(BufferPool *pool, BufferPoolBlock *block);
static void bufferpoolblock_free_buffer(BufferPoolBlock *block, Buffer *buf);

/*
 * Buffer pool block header
 */
struct BufferPoolBlock {
	BufferPool      *pool;     /**< owner buffer pool. */
	LIST_ENTRY(BufferPoolBlock) blocks; /**< next/prev block */
	uint32_t        free_len;  /**< total free space in this block (in bytes not units). */
	buflen_t        next_free; /**< index to next free buffer. */
};

/* total byte length of each block in the pool. */
#define BUFFER_POOL_BLOCK_LENGTH (BUFFER_UNITS * (1<< (sizeof(buflen_t) * 8)))
/* total byte length of the block header rounded to an even number of BUFFER_UNITS. */
#define BUFFER_POOL_BLOCK_HEADER_SIZE \
	(BUFFER_UNITS_LEN(sizeof(BufferPoolBlock)) * BUFFER_UNITS)
/* amount of fixed overhead in each block. */
#define BUFFER_POOL_BLOCK_OVERHEAD \
	(BUFFER_POOL_BLOCK_HEADER_SIZE /* block header */ + BUFFER_UNITS /* last buffer (size == 0) */)
/* total usable length of each block. */
#define BUFFER_POOL_BLOCK_USABLE_LENGTH (BUFFER_POOL_BLOCK_LENGTH - BUFFER_POOL_BLOCK_OVERHEAD)

/* get pointer to a buffer in a block. */
#define BUFFER_POOL_BLOCK_TO_BUFFER(block, idx) \
	(Buffer *)(((uint8_t *)(block)) + ((idx) * BUFFER_UNITS))
/* index of first buffer in block. */
#define BUFFER_POOL_BLOCK_FIRST_BUFFER (BUFFER_POOL_BLOCK_HEADER_SIZE / BUFFER_UNITS)
/* index of last buffer in block. */
#define BUFFER_POOL_BLOCK_LAST_BUFFER ((1<< (sizeof(buflen_t) * 8)) - 1)

/*
 * Buffer.
 */
static Buffer *buffer_get_next(Buffer *buf) {
	return (Buffer *)BUFFER_OFFSET_ADD(buf, buf->size);
}

BufferPool *buffer_get_pool(Buffer *buf) {
	BufferPoolBlock *block;
	BUFFER_VALID(buf);
	block = (BufferPoolBlock *)BUFFER_OFFSET_SUB(buf, buf->block);
	return block->pool;
}

void buffer_free(Buffer *buf) {
	BufferPoolBlock *block;
	BUFFER_VALID(buf);
	/* check if buffer is already free. */
	if(buffer_is_free(buf)) return;
	/* mark buffer as free. */
	buf->len = 0;
	/* tell owner block that the buffer is free. */
	block = (BufferPoolBlock *)BUFFER_OFFSET_SUB(buf, buf->block);
	bufferpoolblock_free_buffer(block, buf);
}

static void buffer_split(Buffer *buf, buflen_t new_size) {
	BufferPoolBlock *block;
	Buffer *next;
	buflen_t extra_size;

	BUFFER_VALID(buf);
	/* calculate extra space. */
	extra_size = buf->size - new_size;
	if(extra_size < BUFFER_MIN_SIZE) {
		/* can't split, free space is too small. */
		return;
	}
	/* we can split this buffer. */
	buf->size = new_size;
	/* create new next buffer. */
	next = buffer_get_next(buf);
	/* make sure the userdata part of the buffer header is cleared. */
	memset(next, 0, sizeof(Buffer));
	next->block = buf->block + new_size;
	next->size = extra_size;
	/* track free space in block. */
	block = (BufferPoolBlock *)BUFFER_OFFSET_SUB(buf, buf->block);
	block->free_len += next->size;
}

void buffer_set_length(Buffer *buf, uint32_t len) {
	buflen_t new_size;
	/* set length. */
	buf->len = len;
	/* calculate new buffer size. */
	new_size = BUFFER_UNITS_LEN(len);
	assert(new_size <= buf->size);
	/* make sure buffer doesn't shrink below min. size. */
	if(new_size < BUFFER_MIN_SIZE) {
		new_size = BUFFER_MIN_SIZE;
	}
	if(new_size == buf->size) {
		/* don't need to split. */
		return;
	}
	buffer_split(buf, new_size);
}


/*
 * Buffer Pool Block
 */
static void bufferpoolblock_reset(BufferPoolBlock *block) {
	Buffer *buf;

	block->free_len = BUFFER_POOL_BLOCK_USABLE_LENGTH;

	/* initialize last buffer. */
	buf = BUFFER_POOL_BLOCK_TO_BUFFER(block, BUFFER_POOL_BLOCK_LAST_BUFFER);
	buf->block = BUFFER_POOL_BLOCK_LAST_BUFFER;
	buf->size = 0; /* mark it as the last buffer. */
	buf->len = 1; /* mark it as non-free. */

	/* initialize first free buffer. */
	block->next_free = BUFFER_POOL_BLOCK_FIRST_BUFFER;
	buf = BUFFER_POOL_BLOCK_TO_BUFFER(block, BUFFER_POOL_BLOCK_FIRST_BUFFER);
	buf->block = BUFFER_POOL_BLOCK_FIRST_BUFFER;
	buf->size = block->free_len / BUFFER_UNITS;
	buf->len = 0; /* mark it as free. */
}

static BufferPoolBlock *bufferpoolblock_new() {
	BufferPoolBlock *block;

	block = (BufferPoolBlock *)malloc(BUFFER_POOL_BLOCK_LENGTH);
	block->pool = NULL;
	/* clear block. */
	bufferpoolblock_reset(block);

	return block;
}

static void bufferpoolblock_free(BufferPoolBlock *block) {
	memset(&(block->blocks), 0, sizeof(block->blocks));
	free(block);
}

static Buffer *bufferpoolblock_get_buffer(BufferPoolBlock *block, uint32_t min_size) {
	Buffer *buf;
	/* get buffer at next free index. */
	buf = BUFFER_POOL_BLOCK_TO_BUFFER(block, block->next_free);
	/* skip to next buffer if this one is still used. */
	while(!buffer_is_free(buf) && !buffer_is_last_buffer(buf)) {
		buf = buffer_get_next(buf);
	}
	if(buffer_size(buf) < min_size) {
		return NULL;
	}
	block->next_free = buf->block;
	/* track free space in block. */
	block->free_len -= buf->size;
	return buf;
}

static void bufferpoolblock_free_buffer(BufferPoolBlock *block, Buffer *buf) {
	Buffer *next;
	/* track free space in this block. */
	block->free_len += buf->size;
	assert(block->free_len <= BUFFER_POOL_BLOCK_USABLE_LENGTH);
	/* check if block is completely free. */
	if(block->free_len == BUFFER_POOL_BLOCK_USABLE_LENGTH) {
		/* block is empty reset it. */
		bufferpoolblock_reset(block);
		/* put block on pool's free list. */
		bufferpool_free_block(block->pool, block);
		return;
	}

	do {
		/* check if next buffer is empty. */
		next = buffer_get_next(buf);
		if(!buffer_is_free(next)) {
			/* can't combind current buffer with next buffer. */
			return;
		}
		/* combind this buffer with next. */
		buf->size += next->size;
		/* combind as many buffers as we can. */
	} while(1);
}

/*
 * Buffer pool header
 */
struct BufferPool {
	LIST_HEAD(usedlist, BufferPoolBlock) used_head;
	LIST_HEAD(freelist, BufferPoolBlock) free_head;
	BufferPoolBlock *cur_block;
	uint32_t total_blocks;
	uint32_t free_blocks;
	size_t min_free_blocks;
	size_t max_free_blocks;
};

static BufferPoolBlock *bufferpool_new_block(BufferPool *pool) {
	BufferPoolBlock *block = bufferpoolblock_new();
	block->pool = pool;
	LIST_INSERT_HEAD(&(pool->free_head), block, blocks);
	pool->free_blocks++;
	pool->total_blocks++;

	return block;
}

BufferPool *bufferpool_new_full(size_t min_free, size_t max_free) {
	BufferPool *pool;
	uint32_t i;

	pool = (BufferPool *)malloc(sizeof(BufferPool));
	pool->total_blocks = 0;
	pool->free_blocks = 0;
	pool->cur_block = NULL;
	if(min_free > BUFFER_POOL_BLOCK_LENGTH) {
		pool->min_free_blocks = min_free / BUFFER_POOL_BLOCK_LENGTH;
	} else {
		pool->min_free_blocks = 1;
	}
	if(max_free > BUFFER_POOL_BLOCK_LENGTH) {
		pool->max_free_blocks = max_free / BUFFER_POOL_BLOCK_LENGTH;
	} else {
		pool->max_free_blocks = 10;
	}
	LIST_INIT(&(pool->used_head));
	LIST_INIT(&(pool->free_head));

	/* pre-allocate blocks. */
	for(i=0; i < pool->min_free_blocks; i++) {
		bufferpool_new_block(pool);
	}

	return pool;
}

void bufferpool_free(BufferPool *pool) {
	BufferPoolBlock *block;

	/* free all blocks.  All blocks should be on the free list. */
	LIST_FOREACH(block, &(pool->free_head), blocks) {
		bufferpoolblock_free(block);
		pool->free_blocks--;
	}
	assert(pool->free_blocks == 0);

	/* make the used lists is empty. */
	assert(LIST_EMPTY(&(pool->used_head)));

	free(pool);
}

static void bufferpool_free_block(BufferPool *pool, BufferPoolBlock *block) {
	/* if block is the cur_block. */
	if(pool->cur_block == block) {
		/* then don't do anything. */
		return;
	}
	/* remove from used block list. */
	LIST_REMOVE(block, blocks);
	/* check if we have to many free blocks. */
	if(pool->free_blocks >= pool->max_free_blocks) {
		pool->total_blocks--;
		bufferpoolblock_free(block);
		return;
	}
	/* add block back to free list. */
	LIST_INSERT_HEAD(&(pool->free_head), block, blocks);
	pool->free_blocks++;
}

static BufferPoolBlock *bufferpool_get_block(BufferPool *pool) {
	BufferPoolBlock *block = pool->cur_block;
	/* return cur_block if it is available. */
	if(block) return block;

	/* need block from free list. */
	block = LIST_FIRST(&(pool->free_head));
	/* check if free list is empty. */
	if(!block) {
		/* allocate new block. */
		block = bufferpool_new_block(pool);
	}

	/* remove free block from free list. */
	LIST_REMOVE(block, blocks);
	pool->free_blocks--;
	/* add block to used list. */
	LIST_INSERT_HEAD(&(pool->used_head), block, blocks);

	/* cache block for faster access. */
	pool->cur_block = block;
	return block;
}

Buffer *bufferpool_get_buffer(BufferPool *pool, uint32_t min_len) {
	BufferPoolBlock *block;
	Buffer *buf;

	assert(min_len <= BUFFER_MAX_LENGTH);
	do {
		/* get a block from the pool. */
		block = bufferpool_get_block(pool);

		buf = bufferpoolblock_get_buffer(block, min_len);
		/* check if we got a buffer, if so return now. */
		if(buf) return buf;

		/* not enought space in buffer, get a new one. */
		pool->cur_block = NULL;
	} while(1);

	return NULL;
}

