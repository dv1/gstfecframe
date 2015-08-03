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


#ifndef GSTFECFRAME_REED_SOLOMON_RSFECENC_H
#define GSTFECFRAME_REED_SOLOMON_RSFECENC_H

#include <gst/gst.h>
#include <of_openfec_api.h>


G_BEGIN_DECLS


typedef struct _GstRSFECEnc GstRSFECEnc;
typedef struct _GstRSFECEncClass GstRSFECEncClass;


#define GST_TYPE_RS_FEC_ENC             (gst_rs_fec_enc_get_type())
#define GST_RS_FEC_ENC(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GST_TYPE_RS_FEC_ENC, GstRSFECEnc))
#define GST_RS_FEC_ENC_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), GST_TYPE_RS_FEC_ENC, GstRSFECEncClass))
#define GST_RS_FEC_ENC_CAST(obj)        ((GstRSFECEnc *)(obj))
#define GST_IS_RS_FEC_ENC(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GST_TYPE_RS_FEC_ENC))
#define GST_IS_RS_FEC_ENC_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), GST_TYPE_RS_FEC_ENC))


struct _GstRSFECEnc
{
	GstElement parent;

	/* Sink- and source pads */
	GstPad *sinkpad, *fecsourcepad, *fecrepairpad;
	/* OpenFEC session handle */
	of_session_t *openfec_session;
	/* Number of source and repair symbols, configured via properties.
	 * These may only be modified if no decoding session is currently
	 * running (that is, if openfec_session == NULL). */
	guint num_source_symbols, num_repair_symbols;
	/* Sum of num_source_symbols and num_repair_symbols */
	guint num_encoding_symbols;
	/* Counter for assigning block numbers to outgoing source blocks.
	 * It is _not_ reset after flushes and PAUSED->READY state changes
	 * This ensures the decoder on the other end does not get confused
	 * because it starts seeing past source block numbers again. */
	guint cur_source_block_nr;
	/* TRUE if no FEC source packet has been pushed downstream yet.
	 * This is set to TRUE at startup, after a flush, and when switching
	 * back state from PAUSED to READY. */
	gboolean first_source_packet;
	/* TRUE if no FEC repair packet has been pushed downstream yet.
	 * This is set to TRUE at startup, after a flush, and when switching
	 * back state from PAUSED to READY. */
	gboolean first_repair_packet;

	/* Length of encoding symbols, in bytes, which are fed into OpenFEC.
	 * Source and repair symbols all have this same length. */
	gsize encoding_symbol_length;
	/* Table containing encoding symbols.
	 * All source symbols come first, followed by the repair symbols
	 * this table is used by OpenFEC.
	 * the table is num_encoding_symbols long.
	 * The array index equals the ESI of the corresponding symbol. */
	void **encoding_symbol_table;

	/* Table for incoming ADUs.
	 * Source block generation can only commence if enough ADUs are present
	 * in the table. The table contains num_source_symbols entries.
	 * Each entry holds a pointer to the GstBuffer that contains the ADU. */
	GstBuffer **adu_table;
	/* Counter for the number of ADUs that have come in so far.
	 * This is incremented when new ADUs come in, and decremented after
	 * each ADU has been processed. It is set to 0 at startup, after a
	 * source block has been successfully generated and sent out, after
	 * a flush, and when switching back state from PAUSED to READY. */
	guint cur_num_adus;
	/* Size of the largest ADU that has been observed so far, in bytes.
	 * This is updated each time an ADU is pushed in the queue, and
	 * used to calculate the encoding_symbol_length once a source block is
	 * generated. */
	gsize cur_max_adu_length;

	/* Table for GstBuffers that hold FEC repair packets.
	 * This table is filled with GstBuffers when a new source block is
	 * created, and cleared afterwards. The table contains
	 * num_repair_symbols entries. */
	GstBuffer **fec_repair_packet_table;
	/* Array containing mapping information for each non-NULL entry in
	 * the fec_repair_packet_table. Since OpenFEC itself has no
	 * callbacks for mapping/unmapping memory, the GstBuffers from
	 * that table have to be mapped prior to the OpenFEC symbol
	 * building calls. This array has num_repair_symbols members. */
	GstMapInfo *fec_repair_packet_map_infos;
	/* Counter for the number of FEC repair packets in the table.
	 * This is set to num_repair_symbols after the table was filled
	 * with GstBuffers, and decremented for each newly built repair
	 * symbol. In case an error occurs while building repair symbols,
	 * that process is aborted, and packets are still in the table.
	 * With the help of this counter, it is then possible to detect
	 * the nonzero amount of still present packets. These leftovers
	 * can then be flushed later. */
	guint cur_num_fec_repair_packets;

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
	/* TRUE if an EOS event was received from upstream.
	 * Queued ADUs and incomplete source blocks will be discarded when
	 * EOS is received, and no more data will be accepted.
	 * this is set to FALSE at startup, after a flush, and when switching
	 * back state from PAUSED to READY. */
	gboolean eos_received;
};


struct _GstRSFECEncClass
{
	GstElementClass parent_class;
};


GType gst_rs_fec_enc_get_type(void);


G_END_DECLS


#endif
