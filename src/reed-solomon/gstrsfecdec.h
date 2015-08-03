/* RFC 6865-based forward error correction based on Reed-Solomon for GStreamer
 * Copyright (C) 2015  Carlos Rafael Giani
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#ifndef GSTFECFRAME_REED_SOLOMON_RSFECDEC_H
#define GSTFECFRAME_REED_SOLOMON_RSFECDEC_H

#include <gst/gst.h>
#include <of_openfec_api.h>


G_BEGIN_DECLS


typedef struct _GstRSFECDec GstRSFECDec;
typedef struct _GstRSFECDecClass GstRSFECDecClass;


#define GST_TYPE_RS_FEC_DEC             (gst_rs_fec_dec_get_type())
#define GST_RS_FEC_DEC(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GST_TYPE_RS_FEC_DEC, GstRSFECDec))
#define GST_RS_FEC_DEC_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), GST_TYPE_RS_FEC_DEC, GstRSFECDecClass))
#define GST_RS_FEC_DEC_CAST(obj)        ((GstRSFECDec *)(obj))
#define GST_IS_RS_FEC_DEC(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GST_TYPE_RS_FEC_DEC))
#define GST_IS_RS_FEC_DEC_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), GST_TYPE_RS_FEC_DEC))


struct _GstRSFECDec
{
	GstElement parent;

	/* Sink- and source pads.
	 * NOTE: fecsourcepad is a sinkpad! "fecsource" refers to
	 * "FEC source packets", not to a sourcepad" */
	GstPad *srcpad, *fecsourcepad, *fecrepairpad;
	/* Number of source and repair symbols, configured via properties.
	 * These may only be modified if no decoding session is currently
	 * running (that is, if allocated_encoding_symbol_table == NULL). */
	guint num_source_symbols, num_repair_symbols;
	/* Sum of num_source_symbols and num_repair_symbols */
	guint num_encoding_symbols;

	/* How old a source block nr can maximally be. "Old" in this context
	 * refers to the distance between the reference block nr (which is
	 * most_recent_block_nr) and another given block nr. If this distance
	 * exceeds the value of max_source_block_age, the given block nr is
	 * considered "too old". This check also wraps around; if
	 * max_source_block_age is 3 and most_recent_block_nr is 1, then
	 * block numbers 1, 0, and (2^24-1) are OK, any between 8e6 and
	 * (2^24-1) are too old, and any between 2 and 8e6 are "newer"
	 * than most_recent_block_nr. */
	guint max_source_block_age;

	/* If TRUE, received and recovered ADUs will get timestamped with
	 * the current running time they are pushed downstream. */
	gboolean do_timestamp;

	/* If TRUE, received and recovered ADUs are pushed downstream in order
	 * of their source block number and ESI. If FALSE, received ADUs are
	 * pushed downstream immediately, regardless of their ESI/source block
	 * number, and recovered ADUs are pushed later. It is useful to
	 * disable this if an element downstream (like an rtpjitterbuffer)
	 * can sort on its own. */
	gboolean sort_output;

	/* TRUE if no ADU has been pushed downstream yet.
	 * This is set to FALSE at startup, after a flush, and when switching
	 * back state from PAUSED to READY. */
	gboolean first_adu;

	/* Length of encoding symbols, in bytes, which are fed into OpenFEC.
	 * Source and repair symbols all have this same length. */
	gsize encoding_symbol_length;

	/* Tables containing encoding symbols.
	 *
	 * All of these tables are num_encoding_symbols long. They
	 * are (re)allocated when the decoder is reconfigured
	 * (= when the encoding symbol length changes).
	 * The array index equals the ESI of the corresponding symbol.
	 * Allocated_encoding_symbol_table contains pointers to all
	 * allocated source symbol memory blocks. (Repair symbols
	 * do not need to be allocated, since they are read from
	 * the FEC repair packets directly.)
	 *
	 * The entries in received_encoding_symbol_table are NULL
	 * if the corresponding symbol was not received. OpenFEC
	 * will try recover all source symbols with NULL entries.
	 *
	 * After OpenFEC is done recovering symbols, each entry in
	 * the recovered_encoding_symbol_table whose corresponding
	 * entry in the received_encoding_symbol_table is NULL
	 * will contain a pointer to a memory block containing
	 * recovered symbol data. In other words, the entries in
	 * recovered_encoding_symbol_table are the result of
	 * the OpenFEC recovery operation.
	 *
	 * All of the pointers in received_encoding_symbol_table and
	 * recovered_encoding_symbol_table are either NULL or the
	 * pointer of the corresponding block in the.
	 * allocated_encoding_symbol_table. For example, if the
	 * pointer of entry 5 in allocated_encoding_symbol_table is
	 * 0x551144, and symbol with ESI 5 was received, then
	 * received_encoding_symbol_table[5] == 0x551144 .
	 * The tables are allocated at startup (NULL->READY state change)
	 * and deallocated when shutting down (READY->NULL state change).
	 */
	void **allocated_encoding_symbol_table;
	void **received_encoding_symbol_table;
	void **recovered_encoding_symbol_table;

	/* Table containing MapInfo instances. Used while a source
	 * block is processed, when the FEC repair packets are mapped
	 * in order for OpenFEC to read the repair symbols. Unlike
	 * the other tables, the indices here do _not_ correspond to
	 * ESIs. */
	GstMapInfo *fec_repair_packet_mapinfos;

	/* Hash table containing all of the incomplete source blocks.
	 * Once a source block is complete (= at least k of its FEC source
	 * packets have arrived), it is processed, and removed from this
	 * table. The hash table's keys are the source block number, the
	 * values are pointers to the incomplete source blocks.
	 * This table is cleared after a flush and after a PAUSED->READY
	 * state change. */
	GHashTable *source_block_table;
	/* If this is TRUE, then no source block pruning has happened yet,
	 * and the next pruning operation will just send most_recent_block_nr
	 * to the number of the outgoing source block (no actual pruning
	 * will take place then). This is set to TRUE at startup, after a
	 * flush, and when switching back state from PAUSED to READY. */
	gboolean first_pruning;
	/* Number of the most recent block number that has been seen in
	 * incoming FEC packets so far. "Most recent" means that this is
	 * the newest block number observed so far. It is used to check
	 * if a source block is too old and needs to be sent out now
	 * (= it needs to be pruned), and if incoming FEC packets have
	 * source block numbers that are too old (in which case the
	 * packets are discarded). */
	guint most_recent_block_nr;

	/* Mutex to ensure FEC source and repair packets queuing and
	 * flushes do not happen concurrently */
	GMutex mutex;

	/* TRUE if a new output segment just started.
	 * If FALSE, then CAPS and SEGMENT events will be pushed downstream
	 * before pushing buffers.
	 * This is set to FALSE at startup, after a flush, and when switching
	 * back state from PAUSED to READY */
	gboolean segment_started;
	/* TRUE if the stream just started.
	 * If FALSE, then a STREAM_START event will be pushed downstream before
	 * anything else is pushed.
	 * this is set to FALSE at startup, and when switching back state
	 * from PAUSED to READY (but not after a flush!) */
	gboolean stream_started;
	/* These are TRUE if EOS events were received from upstream
	 * via the fecsource/fecrepair pads.
	 * Once both of these are TRUE, an EOS event will be pushed downstream.
	 * Incomplete source blocks will then be discarded, and no more
	 * input data will be accepted.
	 * These are set to FALSE at startup, after a flush, and when switching
	 * back state from PAUSED to READY. */
	gboolean fecsource_eos, fecrepair_eos;
};


struct _GstRSFECDecClass
{
	GstElementClass parent_class;
};


GType gst_rs_fec_dec_get_type(void);


G_END_DECLS


#endif
