/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef EVBUFFER_INTERNAL_H_INCLUDED_
#define EVBUFFER_INTERNAL_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#include "event2/event-config.h"
#include "evconfig-private.h"
#include "event2/util.h"
#include "event2/event_struct.h"
#include "util-internal.h"
#include "defer-internal.h"

/* Experimental cb flag: "never deferred."  Implementation note:
 * these callbacks may get an inaccurate view of n_del/n_added in their
 * arguments. */
#define EVBUFFER_CB_NODEFER 2

#ifdef _WIN32
#include <winsock2.h>
#endif
#include <sys/queue.h>

/* Minimum allocation for a chain.  We define this so that we're burning no
 * more than 5% of each allocation on overhead.  It would be nice to lose even
 * less space, though. */
#if EVENT__SIZEOF_VOID_P < 8
#define MIN_BUFFER_SIZE	512
#else
#define MIN_BUFFER_SIZE	1024
#endif

/** A single evbuffer callback for an evbuffer. This function will be invoked
 * when bytes are added to or removed from the evbuffer. */
//evbuf 回调，当在evbuffer中添加或者删除数据时
struct evbuffer_cb_entry {
	/** Structures to implement a doubly-linked queue of callbacks */
    //宏展开为
    //struct {
    //  evbuffer_cb_entry* le_next;
    //  evbuffer_cb_entry** le_prev;
    //}next;
	LIST_ENTRY(evbuffer_cb_entry) next;
	/** The callback function to invoke when this callback is called.
	    If EVBUFFER_CB_OBSOLETE is set in flags, the cb_obsolete field is
	    valid; otherwise, cb_func is valid. */
    //字段有效通过flags指示，发生回调时，将调用指定的回调函数
	union {
        //void (*evbuffer_cb_func)(struct evbuffer *buffer, const struct evbuffer_cb_info *info, void *arg);
		evbuffer_cb_func cb_func;
		evbuffer_cb cb_obsolete;
	} cb;
	/** Argument to pass to cb. */
    //用户数据
	void *cbarg;
	/** Currently set flags on this callback. */
    //指示使用哪一个回调函数
	ev_uint32_t flags;
};
//应用层使用的buffer，evbuffer被封装在此里
struct bufferevent;
//真正装数据的block，在evbuffer中使用链表管理
struct evbuffer_chain;
//管理evbuffer_chain，回调函数，从属于bufferevent
struct evbuffer {
	/** The first chain in this buffer's linked list of chains. */
    //表头指针
	struct evbuffer_chain *first;
	/** The last chain in this buffer's linked list of chains. */
    //表尾指针
	struct evbuffer_chain *last;

	/** Pointer to the next pointer pointing at the 'last_with_data' chain.
	 *
	 * To unpack:
	 *
	 * The last_with_data chain is the last chain that has any data in it.
	 * If all chains in the buffer are empty, it is the first chain.
	 * If the buffer has no chains, it is NULL.
	 *
	 * The last_with_datap pointer points at _whatever 'next' pointer_
	 * pointing at the last_with_data chain. If the last_with_data chain
	 * is the first chain, or it is NULL, then the last_with_datap pointer
	 * is &buf->first.
	 */
    //最后一个有数据的节点被next指向的指针的地址，如果没有数据，将为&buf->first,目的是是为了在写入数据时，迅速找到写入的位置
	struct evbuffer_chain **last_with_datap;

	/** Total amount of bytes stored in all chains.*/
    //链表中所有的数据长度
	size_t total_len;

	/** Number of bytes we have added to the buffer since we last tried to
	 * invoke callbacks. */
    //最后一次调用回调函数后，新增的数据长度
	size_t n_add_for_cb;
	/** Number of bytes we have removed from the buffer since we last
	 * tried to invoke callbacks. */
    //最后一次调用回调函数后，删除的数据
	size_t n_del_for_cb;
    //锁的颗粒度是整个链表
#ifndef EVENT__DISABLE_THREAD_SUPPORT
	/** A lock used to mediate access to this buffer. */
    //锁，用于并发
	void *lock;
#endif
	/** True iff we should free the lock field when we free this
	 * evbuffer. */
    //释放evbuff时，是否要释放锁
	unsigned own_lock : 1;
	/** True iff we should not allow changes to the front of the buffer
	 * (drains or prepends). */
    //起始的buffer是否允许改动
	unsigned freeze_start : 1;
	/** True iff we should not allow changes to the end of the buffer
	 * (appends) */
    //结尾的buffer是否允许改动
	unsigned freeze_end : 1;
	/** True iff this evbuffer's callbacks are not invoked immediately
	 * upon a change in the buffer, but instead are deferred to be invoked
	 * from the event_base's loop.	Useful for preventing enormous stack
	 * overflows when we have mutually recursive callbacks, and for
	 * serializing callbacks in a single thread. */
    //推迟buffer改变时的调用函数
	unsigned deferred_cbs : 1;
#ifdef _WIN32
	/** True iff this buffer is set up for overlapped IO. */
	unsigned is_overlapped : 1;
#endif
	/** Zero or more EVBUFFER_FLAG_* bits */
	ev_uint32_t flags;

	/** Used to implement deferred callbacks. */
    //延迟调用，管理事件调用
	struct event_base *cb_queue;

	/** A reference count on this evbuffer.	 When the reference count
	 * reaches 0, the buffer is destroyed.	Manipulated with
	 * evbuffer_incref and evbuffer_decref_and_unlock and
	 * evbuffer_free. */
    //引用计数，如果为0，将释放此buffer
	int refcnt;

	/** A struct event_callback handle to make all of this buffer's callbacks
	 * invoked from the event loop. */
    //事件的回调函数结构体
	struct event_callback deferred;

	/** A doubly-linked-list of callback functions */
    //读写的回调函数head
    //宏展开为：
    //struct evbuffer_cb_queue { 
    //  evbuffer_cb_entry* lh_first;
    //}callbacks;
	LIST_HEAD(evbuffer_cb_queue, evbuffer_cb_entry) callbacks;

	/** The parent bufferevent object this evbuffer belongs to.
	 * NULL if the evbuffer stands alone. */
    //所属的bufferevent
	struct bufferevent *parent;
};

#if EVENT__SIZEOF_OFF_T < EVENT__SIZEOF_SIZE_T
typedef ev_ssize_t ev_misalign_t;
#define EVBUFFER_CHAIN_MAX ((size_t)EV_SSIZE_MAX)
#else
typedef ev_off_t ev_misalign_t;
#if EVENT__SIZEOF_OFF_T > EVENT__SIZEOF_SIZE_T
#define EVBUFFER_CHAIN_MAX EV_SIZE_MAX
#else
#define EVBUFFER_CHAIN_MAX ((size_t)EV_SSIZE_MAX)
#endif
#endif

/** A single item in an evbuffer. */
struct evbuffer_chain {
    //单链表形式，定义evbuffer链表节点,数据在buf是连续的，开始位置不一定是0，可能是misalign，实际长度是off
	/** points to next buffer in the chain */
    //链表指针
	struct evbuffer_chain *next;

	/** total allocation available in the buffer field. */
    //分配的容量
	size_t buffer_len;

	/** unused space at the beginning of buffer or an offset into a
	 * file for sendfile buffers. */
    //开始未用的大小
	ev_misalign_t misalign;

	/** Offset into buffer + misalign at which to start writing.
	 * In other words, the total number of bytes actually stored
	 * in buffer. */
    //真正的数据长度，在buf中的位置为[misalign,misalign+off);
	size_t off;

	/** Set if special handling is required for this chain */
    //设置buf指向的内容的属性
	unsigned flags;
#define EVBUFFER_FILESEGMENT	0x0001  /**< A chain used for a file segment */
#define EVBUFFER_SENDFILE	0x0002	/**< a chain used with sendfile */
#define EVBUFFER_REFERENCE	0x0004	/**< a chain with a mem reference */
#define EVBUFFER_IMMUTABLE	0x0008	/**< read-only chain */
	/** a chain that mustn't be reallocated or freed, or have its contents
	 * memmoved, until the chain is un-pinned. */
#define EVBUFFER_MEM_PINNED_R	0x0010
#define EVBUFFER_MEM_PINNED_W	0x0020
#define EVBUFFER_MEM_PINNED_ANY (EVBUFFER_MEM_PINNED_R|EVBUFFER_MEM_PINNED_W)
	/** a chain that should be freed, but can't be freed until it is
	 * un-pinned. */
#define EVBUFFER_DANGLING	0x0040
	/** a chain that is a referenced copy of another chain */
#define EVBUFFER_MULTICAST	0x0080

	/** number of references to this chain */
    //引用计数器
	int refcnt;

	/** Usually points to the read-write memory belonging to this
	 * buffer allocated as part of the evbuffer_chain allocation.
	 * For mmap, this can be a read-only buffer and
	 * EVBUFFER_IMMUTABLE will be set in flags.  For sendfile, it
	 * may point to NULL.
	 */
    //指向内存的开始，或者在其他情况下为NULL
	unsigned char *buffer;
};

/** callback for a reference chain; lets us know what to do with it when
 * we're done with it. Lives at the end of an evbuffer_chain with the
 * EVBUFFER_REFERENCE flag set */
//typedef void (*evbuffer_ref_cleanup_cb)(const void *data,
//    size_t datalen, void *extra);
struct evbuffer_chain_reference {
	evbuffer_ref_cleanup_cb cleanupfn;
	void *extra;
};

/** File segment for a file-segment chain.  Lives at the end of an
 * evbuffer_chain with the EVBUFFER_FILESEGMENT flag set.  */
struct evbuffer_chain_file_segment {
	struct evbuffer_file_segment *segment;
#ifdef _WIN32
	/** If we're using CreateFileMapping, this is the handle to the view. */
	HANDLE view_handle;
#endif
};

/* Declared in event2/buffer.h; defined here. */
struct evbuffer_file_segment {
	void *lock; /**< lock prevent concurrent access to refcnt */
	int refcnt; /**< Reference count for this file segment */
	unsigned flags; /**< combination of EVBUF_FS_* flags  */

	/** What kind of file segment is this? */
	unsigned can_sendfile : 1;
	unsigned is_mapping : 1;

	/** The fd that we read the data from. */
	int fd;
	/** If we're using mmap, this is the raw mapped memory. */
	void *mapping;
#ifdef _WIN32
	/** If we're using CreateFileMapping, this is the mapping */
	HANDLE mapping_handle;
#endif
	/** If we're using mmap or IO, this is the content of the file
	 * segment. */
	char *contents;
	/** Position of this segment within the file. */
	ev_off_t file_offset;
	/** If we're using mmap, this is the offset within 'mapping' where
	 * this data segment begins. */
	ev_off_t mmap_offset;
	/** The length of this segment. */
	ev_off_t length;
	/** Cleanup callback function */
	evbuffer_file_segment_cleanup_cb cleanup_cb;
	/** Argument to be pass to cleanup callback function */
	void *cleanup_cb_arg;
};

/** Information about the multicast parent of a chain.  Lives at the
 * end of an evbuffer_chain with the EVBUFFER_MULTICAST flag set.  */
struct evbuffer_multicast_parent {
	/** source buffer the multicast parent belongs to */
	struct evbuffer *source;
	/** multicast parent for this chain */
	struct evbuffer_chain *parent;
};

#define EVBUFFER_CHAIN_SIZE sizeof(struct evbuffer_chain)
/** Return a pointer to extra data allocated along with an evbuffer. */
#define EVBUFFER_CHAIN_EXTRA(t, c) (t *)((struct evbuffer_chain *)(c) + 1)

/** Assert that we are holding the lock on an evbuffer */
#define ASSERT_EVBUFFER_LOCKED(buffer)			\
	EVLOCK_ASSERT_LOCKED((buffer)->lock)

#define EVBUFFER_LOCK(buffer)						\
	do {								\
		EVLOCK_LOCK((buffer)->lock, 0);				\
	} while (0)
#define EVBUFFER_UNLOCK(buffer)						\
	do {								\
		EVLOCK_UNLOCK((buffer)->lock, 0);			\
	} while (0)
#define EVBUFFER_LOCK2(buffer1, buffer2)				\
	do {								\
		EVLOCK_LOCK2((buffer1)->lock, (buffer2)->lock, 0, 0);	\
	} while (0)
#define EVBUFFER_UNLOCK2(buffer1, buffer2)				\
	do {								\
		EVLOCK_UNLOCK2((buffer1)->lock, (buffer2)->lock, 0, 0);	\
	} while (0)

/** Increase the reference count of buf by one. */
//增加evbuffer的引用计数
void evbuffer_incref_(struct evbuffer *buf);
/** Increase the reference count of buf by one and acquire the lock. */
//增加引用计数并且获取锁
void evbuffer_incref_and_lock_(struct evbuffer *buf);
/** Pin a single buffer chain using a given flag. A pinned chunk may not be
 * moved or freed until it is unpinned. */
//操作evbuffer_chain，标记为flag
void evbuffer_chain_pin_(struct evbuffer_chain *chain, unsigned flag);
/** Unpin a single buffer chain using a given flag. */
//操作evbuffer_chain，去掉标记flag
void evbuffer_chain_unpin_(struct evbuffer_chain *chain, unsigned flag);
/** As evbuffer_free, but requires that we hold a lock on the buffer, and
 * releases the lock before freeing it and the buffer. */
void evbuffer_decref_and_unlock_(struct evbuffer *buffer);

/** As evbuffer_expand, but does not guarantee that the newly allocated memory
 * is contiguous.  Instead, it may be split across two or more chunks. */
int evbuffer_expand_fast_(struct evbuffer *, size_t, int);

/** Helper: prepares for a readv/WSARecv call by expanding the buffer to
 * hold enough memory to read 'howmuch' bytes in possibly noncontiguous memory.
 * Sets up the one or two iovecs in 'vecs' to point to the free memory and its
 * extent, and *chainp to point to the first chain that we'll try to read into.
 * Returns the number of vecs used.
 */
int evbuffer_read_setup_vecs_(struct evbuffer *buf, ev_ssize_t howmuch,
    struct evbuffer_iovec *vecs, int n_vecs, struct evbuffer_chain ***chainp,
    int exact);

/* Helper macro: copies an evbuffer_iovec in ei to a win32 WSABUF in i. */
#define WSABUF_FROM_EVBUFFER_IOV(i,ei) do {		\
		(i)->buf = (ei)->iov_base;		\
		(i)->len = (unsigned long)(ei)->iov_len;	\
	} while (0)
/* XXXX the cast above is safe for now, but not if we allow mmaps on win64.
 * See note in buffer_iocp's launch_write function */

/** Set the parent bufferevent object for buf to bev */
void evbuffer_set_parent_(struct evbuffer *buf, struct bufferevent *bev);

void evbuffer_invoke_callbacks_(struct evbuffer *buf);


int evbuffer_get_callbacks_(struct evbuffer *buffer,
    struct event_callback **cbs,
    int max_cbs);

#ifdef __cplusplus
}
#endif

#endif /* EVBUFFER_INTERNAL_H_INCLUDED_ */
