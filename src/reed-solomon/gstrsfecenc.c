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


/**
 * GstRSFECEnc is an encoder element that implements RFC 6865 for application-
 * level forward error correction (more precisely, erasure coding) by using the
 * Reed-Solomon algorithm.
 *
 * The RFC 6865 terminology is used here. Please consult this RFC if you
 * do not know what "ADU", "FEC source packets" etc. mean. This includes
 * the meanings of the "k" and "n" values. (Regarding the element properties,
 * k = num_source_symbols , and n = num_encoding_symbols.)
 *
 * Reed-Solomon is stricly used for erasure coding, *not* for detecting and
 * correcting corrupted symbols. The underlying transport layer must take
 * care of detecting and discarding corrupted data.
 *
 * The Reed-Solomon implementation in the OpenFEC library is used for
 * generating repair symbols and recovering lost source symbols (if enough
 * encoding symbols have been received).
 *
 * The encoder element works by pushing incoming ADUs into two parts:
 * the first part is the FEC source packet generation. Such packets are
 * immediately generated out of ADUs and pushed downstream to the fecsource
 * pad. This way, the encoder does not cause any latencies in the source
 * data. The ADU is also pushed into a queue. Once this queue has enough
 * ADUs inside (exactly k ADUs), a new source block can be generated. The
 * encoder then creates ADUIs (= source symbols) out of ADUs. The ADUIs are
 * fed into the OpenFEC encoder session, which then builds repair symbols out
 * of these ADUIs. The repair symbols are prepended with a FEC payload ID,
 * turning them into FEC repair packets. These packets are then pushed
 * downstream to the fecrepair pad.
 *
 * If num_repair_symbols is set to 0, the element behaves as usual, except
 * that it does not build any repair symbols, and therefore does not push
 * any FEC repair packets downstream.
 *
 * IMPORTANT: ADUs must not be larger than 65535 bytes, since the length value
 * in ADUIs are 16-bit unsigned integers, as specified in the RFC. This element
 * does not do any ADU splitting; upstream must take care of that.
 */


/* NOTE: Currently, only GF(2^8) Reed-Solomon is supported. RFC 6865 however also
 * mentions support for GF(2^m), where 2 <= m <= 16. OpenFEC currently does not support
 * GF(2^m) unless m is 4 or 8. Therefore, only GF(2^8) is supported in this element
 * for now. Once OpenFEC has been extended to support the necessary range for m,
 * reevaluate. */


#include <string.h>
#include "gstrsfecenc.h"


GST_DEBUG_CATEGORY(rs_fec_enc_debug);
#define GST_CAT_DEFAULT rs_fec_enc_debug

enum
{
	PROP_0,
	PROP_NUM_SOURCE_SYMBOLS,
	PROP_NUM_REPAIR_SYMBOLS
};


#define DEFAULT_NUM_SOURCE_SYMBOLS 4
#define DEFAULT_NUM_REPAIR_SYMBOLS 2


#define FEC_SOURCE_CAPS_STR "application/x-fec-source-flow, encoding-id = (int) 8"
#define FEC_REPAIR_CAPS_STR "application/x-fec-repair-flow, encoding-id = (int) 8"


#define FEC_PAYLOAD_ID_LENGTH 6


#define CHECK_IF_FATAL_ERROR(elem, status) \
	do { \
		if ((status) == OF_STATUS_FATAL_ERROR) \
			GST_ELEMENT_ERROR((elem), LIBRARY, FAILED, ("OpenFEC reports fatal error"), (NULL)); \
	} while (0)


static GstStaticPadTemplate static_sink_template = GST_STATIC_PAD_TEMPLATE(
	"sink",
	GST_PAD_SINK,
	GST_PAD_ALWAYS,
	GST_STATIC_CAPS_ANY
);


static GstStaticPadTemplate static_fecsource_template = GST_STATIC_PAD_TEMPLATE(
	"fecsource",
	GST_PAD_SRC,
	GST_PAD_ALWAYS,
	GST_STATIC_CAPS(FEC_SOURCE_CAPS_STR)
);


static GstStaticPadTemplate static_fecrepair_template = GST_STATIC_PAD_TEMPLATE(
	"fecrepair",
	GST_PAD_SRC,
	GST_PAD_ALWAYS,
	GST_STATIC_CAPS(FEC_REPAIR_CAPS_STR)
);




G_DEFINE_TYPE(GstRSFECEnc, gst_rs_fec_enc, GST_TYPE_ELEMENT)


static void gst_rs_fec_enc_set_property(GObject *object, guint prop_id, GValue const *value, GParamSpec *pspec);
static void gst_rs_fec_enc_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);

static GstStateChangeReturn gst_rs_fec_enc_change_state(GstElement *element, GstStateChange transition);

static gboolean gst_rs_fec_enc_sink_event(GstPad *pad, GstObject *parent, GstEvent *event);
static GstFlowReturn gst_rs_fec_enc_sink_chain(GstPad *pad, GstObject *parent, GstBuffer *buffer);

static void gst_rs_fec_enc_alloc_encoding_symbol_table(GstRSFECEnc *rs_fec_enc);
static void gst_rs_fec_enc_free_encoding_symbol_table(GstRSFECEnc *rs_fec_enc);
static void gst_rs_fec_enc_alloc_adu_table(GstRSFECEnc *rs_fec_enc);
static void gst_rs_fec_enc_free_adu_table(GstRSFECEnc *rs_fec_enc);
static void gst_rs_fec_enc_alloc_fec_repair_packet_table(GstRSFECEnc *rs_fec_enc);
static void gst_rs_fec_enc_free_fec_repair_packet_table(GstRSFECEnc *rs_fec_enc);

static gboolean gst_rs_fec_enc_init_openfec(GstRSFECEnc *rs_fec_enc);
static gboolean gst_rs_fec_enc_shutdown_openfec(GstRSFECEnc *rs_fec_enc);
static gboolean gst_rs_fec_enc_configure_fec(GstRSFECEnc *rs_fec_enc, gsize symbol_length);

static void gst_rs_fec_enc_insert_adu(GstRSFECEnc *rs_fec_enc, GstBuffer *adu, guint esi);
static GstFlowReturn gst_rs_fec_enc_push_adu(GstRSFECEnc *rs_fec_enc, GstBuffer *adu, guint esi);
static void gst_rs_fec_enc_flush_all_adus(GstRSFECEnc *rs_fec_enc);
static void gst_rs_fec_enc_flush_all_fec_repair_packets(GstRSFECEnc *rs_fec_enc);
static void gst_rs_fec_enc_free_payload_id(gpointer data);
static GstFlowReturn gst_rs_fec_enc_process_source_block(GstRSFECEnc *rs_fec_enc);
static void gst_rs_fec_enc_reset_states(GstRSFECEnc *rs_fec_enc);
static void gst_rs_fec_enc_flush(GstRSFECEnc *rs_fec_enc);
static gchar const * gst_rs_fec_enc_get_status_name(of_status_t status);



static void gst_rs_fec_enc_class_init(GstRSFECEncClass *klass)
{
	GObjectClass *object_class;
	GstElementClass *element_class;

	GST_DEBUG_CATEGORY_INIT(rs_fec_enc_debug, "rsfecenc", 0, "FECFRAME RFC 6865 Reed-Solomon scheme encoder");

	object_class = G_OBJECT_CLASS(klass);
	element_class = GST_ELEMENT_CLASS(klass);

	gst_element_class_add_pad_template(element_class, gst_static_pad_template_get(&static_sink_template));
	gst_element_class_add_pad_template(element_class, gst_static_pad_template_get(&static_fecsource_template));
	gst_element_class_add_pad_template(element_class, gst_static_pad_template_get(&static_fecrepair_template));

	object_class->set_property  = GST_DEBUG_FUNCPTR(gst_rs_fec_enc_set_property);
	object_class->get_property  = GST_DEBUG_FUNCPTR(gst_rs_fec_enc_get_property);

	element_class->change_state = GST_DEBUG_FUNCPTR(gst_rs_fec_enc_change_state);

	g_object_class_install_property(
		object_class,
		PROP_NUM_SOURCE_SYMBOLS,
		g_param_spec_uint(
			"num-source-symbols",
			"Number of source symbols",
			"How many source symbols to use per Reed-Solomon source block",
			1, G_MAXUINT,
			DEFAULT_NUM_SOURCE_SYMBOLS,
			G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS
		)
	);
	g_object_class_install_property(
		object_class,
		PROP_NUM_REPAIR_SYMBOLS,
		g_param_spec_uint(
			"num-repair-symbols",
			"Number of repair symbols",
			"How many repair symbols to use per Reed-Solomon repair block (0 disables FEC repair symbol generation)",
			0, G_MAXUINT,
			DEFAULT_NUM_REPAIR_SYMBOLS,
			G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS
		)
	);

	gst_element_class_set_static_metadata(
		element_class,
		"Reed-Solomon forward error correction encoder",
		"Codec/Encoder/Network",
		"Produces forward-error erasure coding based on the FECFRAME Reed-Solomon scheme RFC 6865",
		"Carlos Rafael Giani <dv@pseudoterminal.org>"
	);
}


static void gst_rs_fec_enc_init(GstRSFECEnc *rs_fec_enc)
{
	rs_fec_enc->openfec_session = NULL;

	rs_fec_enc->num_source_symbols = DEFAULT_NUM_SOURCE_SYMBOLS;
	rs_fec_enc->num_repair_symbols = DEFAULT_NUM_REPAIR_SYMBOLS;
	rs_fec_enc->num_encoding_symbols = rs_fec_enc->num_source_symbols + rs_fec_enc->num_repair_symbols;
	rs_fec_enc->cur_source_block_nr = 0;
	rs_fec_enc->first_source_packet = TRUE;
	rs_fec_enc->first_repair_packet = TRUE;

	rs_fec_enc->encoding_symbol_length = 0;
	rs_fec_enc->encoding_symbol_table = NULL;

	rs_fec_enc->adu_table = NULL;
	rs_fec_enc->cur_num_adus = 0;
	rs_fec_enc->cur_max_adu_length = 0;

	rs_fec_enc->fec_repair_packet_table = NULL;
	rs_fec_enc->cur_num_fec_repair_packets = 0;

	rs_fec_enc->segment_started = FALSE;
	rs_fec_enc->stream_started = FALSE;
	rs_fec_enc->eos_received = FALSE;

	rs_fec_enc->sinkpad = gst_ghost_pad_new_no_target_from_template(
		"sink",
		gst_element_class_get_pad_template(GST_ELEMENT_GET_CLASS(rs_fec_enc), "sink")
	);
	gst_element_add_pad(GST_ELEMENT(rs_fec_enc), rs_fec_enc->sinkpad);

	rs_fec_enc->fecsourcepad = gst_ghost_pad_new_no_target_from_template(
		"fecsource",
		gst_element_class_get_pad_template(GST_ELEMENT_GET_CLASS(rs_fec_enc), "fecsource")
	);
	gst_element_add_pad(GST_ELEMENT(rs_fec_enc), rs_fec_enc->fecsourcepad);

	rs_fec_enc->fecrepairpad = gst_ghost_pad_new_no_target_from_template(
		"fecrepair",
		gst_element_class_get_pad_template(GST_ELEMENT_GET_CLASS(rs_fec_enc), "fecrepair")
	);
	gst_element_add_pad(GST_ELEMENT(rs_fec_enc), rs_fec_enc->fecrepairpad);

	gst_pad_set_event_function(rs_fec_enc->sinkpad, GST_DEBUG_FUNCPTR(gst_rs_fec_enc_sink_event));
	gst_pad_set_chain_function(rs_fec_enc->sinkpad, GST_DEBUG_FUNCPTR(gst_rs_fec_enc_sink_chain));
}


static void gst_rs_fec_enc_set_property(GObject *object, guint prop_id, GValue const *value, GParamSpec *pspec)
{
	GstRSFECEnc *rs_fec_enc = GST_RS_FEC_ENC(object);

	/* NOTE: this assumes Reed-Solomon with GF(2^8) is used
	 * once OpenFEC can handle GF(2^m) with 2 <= m <= 16,
	 * replace this constant with something appropriate */
	guint const max_num_encoding_symbols = (1 << 8) - 1;

	switch (prop_id)
	{
		case PROP_NUM_SOURCE_SYMBOLS:
			GST_OBJECT_LOCK(object);
			if (rs_fec_enc->openfec_session == NULL)
			{
				rs_fec_enc->num_source_symbols = g_value_get_uint(value);
				rs_fec_enc->num_encoding_symbols = rs_fec_enc->num_source_symbols + rs_fec_enc->num_repair_symbols;
				if (rs_fec_enc->num_encoding_symbols > max_num_encoding_symbols)
				{
					GST_ELEMENT_ERROR(
						object, LIBRARY, SETTINGS,
						("invalid total number of encoding symbols"),
						("number of source symbols: %u  repair symbols: %u  source+repair: %u  maximum allowed: %u", rs_fec_enc->num_source_symbols, rs_fec_enc->num_repair_symbols, rs_fec_enc->num_encoding_symbols, max_num_encoding_symbols)
					);
				}
			}
			else
				GST_ELEMENT_WARNING(object, LIBRARY, SETTINGS, ("cannot set number of source symbols after initializing OpenFEC"), (NULL));
			GST_OBJECT_UNLOCK(object);
			break;

		case PROP_NUM_REPAIR_SYMBOLS:
			GST_OBJECT_LOCK(object);
			if (rs_fec_enc->openfec_session == NULL)
			{
				rs_fec_enc->num_repair_symbols = g_value_get_uint(value);
				rs_fec_enc->num_encoding_symbols = rs_fec_enc->num_source_symbols + rs_fec_enc->num_repair_symbols;
				if (rs_fec_enc->num_encoding_symbols > max_num_encoding_symbols)
				{
					GST_ELEMENT_ERROR(
						object, LIBRARY, SETTINGS,
						("invalid total number of encoding symbols"),
						("number of source symbols: %u  repair symbols: %u  source+repair: %u  maximum allowed: %u", rs_fec_enc->num_source_symbols, rs_fec_enc->num_repair_symbols, rs_fec_enc->num_encoding_symbols, max_num_encoding_symbols)
					);
				}
			}
			else
				GST_ELEMENT_WARNING(object, LIBRARY, SETTINGS, ("cannot set number of repair symbols after initializing OpenFEC"), (NULL));
			GST_OBJECT_UNLOCK(object);
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}


static void gst_rs_fec_enc_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	GstRSFECEnc *rs_fec_enc = GST_RS_FEC_ENC(object);

	switch (prop_id)
	{
		case PROP_NUM_SOURCE_SYMBOLS:
			g_value_set_uint(value, rs_fec_enc->num_source_symbols);
			break;

		case PROP_NUM_REPAIR_SYMBOLS:
			g_value_set_uint(value, rs_fec_enc->num_repair_symbols);
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}


static GstStateChangeReturn gst_rs_fec_enc_change_state(GstElement *element, GstStateChange transition)
{
	GstRSFECEnc *rs_fec_enc = GST_RS_FEC_ENC(element);
	GstStateChangeReturn result;

	switch (transition)
	{
		case GST_STATE_CHANGE_NULL_TO_READY:
			if (!gst_rs_fec_enc_init_openfec(rs_fec_enc))
				return GST_STATE_CHANGE_FAILURE;
			break;

		case GST_STATE_CHANGE_READY_TO_PAUSED:
			/* Make sure states are at their initial value */
			gst_rs_fec_enc_reset_states(rs_fec_enc);
			break;

		default:
			break;
	}

	if ((result = GST_ELEMENT_CLASS(gst_rs_fec_enc_parent_class)->change_state(element, transition)) == GST_STATE_CHANGE_FAILURE)
		return result;

	switch (transition)
	{
		case GST_STATE_CHANGE_PAUSED_TO_READY:
			/* Make sure any stored ADUs are flushed and states are reset properly */
			gst_rs_fec_enc_flush(rs_fec_enc);
			/* Stream is done after switching to READY */
			rs_fec_enc->stream_started = FALSE;
			break;

		case GST_STATE_CHANGE_READY_TO_NULL:
			if (!gst_rs_fec_enc_shutdown_openfec(rs_fec_enc))
				return GST_STATE_CHANGE_FAILURE;
			break;
		default:
			break;
	}

	return result;
}


static gboolean gst_rs_fec_enc_sink_event(GstPad *pad, GstObject *parent, GstEvent *event)
{
	GstRSFECEnc *rs_fec_enc = GST_RS_FEC_ENC(parent);

	switch (GST_EVENT_TYPE(event))
	{
		case GST_EVENT_STREAM_START:
			/* Throw away incoming STREAM_START events
			 * this encoder generates its own STREAM_START events */
			gst_event_unref(event);
			return TRUE;

		case GST_EVENT_CAPS:
			/* Throw away incoming caps
			 * this encoder generates its own CAPS events */
			gst_event_unref(event);
			return TRUE;

		case GST_EVENT_SEGMENT:
			/* Throw away incoming segments
			 * this encoder generates its own SEGMENT events */
			gst_event_unref(event);
			return TRUE;

		case GST_EVENT_FLUSH_STOP:
			/* Make sure any stored ADUs are flushed and states are reset properly */
			gst_rs_fec_enc_flush(rs_fec_enc);
			break;

		case GST_EVENT_EOS:
			GST_DEBUG_OBJECT(rs_fec_enc, "EOS received");

			/* Set the eos_received flag to let the chain function know we are done
			 * receiving data, and forward the EOS event to both sourcepads */
			rs_fec_enc->eos_received = TRUE;

			/* Ref the event, since it is pushed downstream twice here
			 * (once for each sourcepad) */
			gst_event_ref(event);
			gst_pad_push_event(rs_fec_enc->fecsourcepad, event);
			gst_pad_push_event(rs_fec_enc->fecrepairpad, event);

			/* After EOS, no data is accepted anymore; might as well flush
			 * whatever is still stored */
			gst_rs_fec_enc_flush_all_adus(rs_fec_enc);
			gst_rs_fec_enc_flush_all_fec_repair_packets(rs_fec_enc);

			return TRUE;

		default:
			break;
	}

	return gst_pad_event_default(pad, parent, event);
}


static GstFlowReturn gst_rs_fec_enc_sink_chain(G_GNUC_UNUSED GstPad *pad, GstObject *parent, GstBuffer *buffer)
{
	GstRSFECEnc *rs_fec_enc = GST_RS_FEC_ENC_CAST(parent);
	GstFlowReturn ret = GST_FLOW_OK;

	if (rs_fec_enc->eos_received)
	{
		GST_DEBUG_OBJECT(rs_fec_enc, "received data after EOS was received - dropping buffer");
		gst_buffer_unref(buffer);
		ret = GST_FLOW_EOS;
	}
	else
	{
		/* The input buffer is the new ADU */

		gsize bufsize = gst_buffer_get_size(buffer);

		if (bufsize > 65535)
		{
			GST_ELEMENT_ERROR(rs_fec_enc, STREAM, ENCODE, ("input buffer too large"), ("maximum is 65535 bytes, buffer size is %" G_GSIZE_FORMAT, bufsize));
			gst_buffer_unref(buffer);
			ret = GST_FLOW_ERROR;
		}
		else
		{
			GstBuffer *output_adu;

			/* The ESI for this new ADU shall be the value of cur_num_adus.
			 * The reason for this is that new ADUs shall be placed one after the
			 * other in the adu_table. So, the first ADU is placed in index 0,
			 * the second in index 1 etc. cur_num_adus therefore functions both
			 * as an index counter for the ESIs and a value denoting the number
			 * of currently present ADUs. */
			guint esi = rs_fec_enc->cur_num_adus;

			/* Copy the ADU. This avoids actually copying the bytes themselves
			 * unless it is deemed absolutely necessary by GStreamer.
			 * The copy is required, because the GstBuffer is modified (an FEC
			 * payload ID is appended prior to sending). */
			output_adu = gst_buffer_copy(buffer);
			if ((ret = gst_rs_fec_enc_push_adu(rs_fec_enc, output_adu, esi)) != GST_FLOW_OK)
			{
				gst_buffer_unref(buffer);
				return ret;
			}

			/* Insert the ADU into the adu_table and update the cur_max_adu_length. */
			gst_rs_fec_enc_insert_adu(rs_fec_enc, buffer, esi);

			/* Increment the counter _before_ processing the block below, since it
			 * expects cur_num_adus to denote the number of inserted ADUs. */
			rs_fec_enc->cur_num_adus++;

			ret = gst_rs_fec_enc_process_source_block(rs_fec_enc);
		}
	}

	return ret;
}


static void gst_rs_fec_enc_alloc_encoding_symbol_table(GstRSFECEnc *rs_fec_enc)
{
	g_assert(rs_fec_enc->encoding_symbol_table == NULL);

	GST_DEBUG_OBJECT(
		rs_fec_enc,
		"allocating encoding symbol ADU table  (num encoding symbols: %u  num source symbols: %u)",
		rs_fec_enc->num_encoding_symbols,
		rs_fec_enc->num_source_symbols
	);

	/* Create encoding symbol table for OpenFEC. In the table, the
	 * source symbols must come in first, in the same order as they
	 * are in the queue. Directly behind the source symbols, the
	 * repair symbols are located. The memory blocks of the
	 * individual symbols are allocated later in the function
	 * gst_rs_fec_enc_configure_fec(). */
	rs_fec_enc->encoding_symbol_table = g_slice_alloc0(sizeof(void *) * rs_fec_enc->num_encoding_symbols);
}


static void gst_rs_fec_enc_free_encoding_symbol_table(GstRSFECEnc *rs_fec_enc)
{
	g_assert(rs_fec_enc->encoding_symbol_table != NULL);

	/* Deallocate symbol memory blocks first */
	if (rs_fec_enc->encoding_symbol_length != 0)
	{
		/* Deallocating the first num_source_symbols, NOT all
		 * num_encoding_symbols. See inside the function
		 * gst_rs_fec_enc_configure_fec() for an explanation. */

		guint i;
		for (i = 0; i < rs_fec_enc->num_source_symbols; ++i)
			g_slice_free1(rs_fec_enc->encoding_symbol_length, rs_fec_enc->encoding_symbol_table[i]);
	}

	/* Then deallocate the table itself */
	g_slice_free1(sizeof(void *) * rs_fec_enc->num_encoding_symbols, rs_fec_enc->encoding_symbol_table);

	rs_fec_enc->encoding_symbol_table = NULL;
}


static void gst_rs_fec_enc_alloc_adu_table(GstRSFECEnc *rs_fec_enc)
{
	g_assert(rs_fec_enc->adu_table == NULL);

	GST_DEBUG_OBJECT(
		rs_fec_enc,
		"allocating ADU table  (num source symbols: %u)",
		rs_fec_enc->num_source_symbols
	);

	/* The ADU table has entries for as many ADUs as are needed
	 * to create a source block. This means that the ADU table
	 * length equals num_source_symbols. Incoming ADUs are placed
	 * in this table. */
	rs_fec_enc->adu_table = g_slice_alloc0(sizeof(GstBuffer *) * rs_fec_enc->num_source_symbols);
}


static void gst_rs_fec_enc_free_adu_table(GstRSFECEnc *rs_fec_enc)
{
	g_assert(rs_fec_enc->adu_table != NULL);
	/* It is assumed that any leftover ADUs have been flushed at this point */
	g_assert(rs_fec_enc->cur_num_adus == 0);
	g_slice_free1(sizeof(GstBuffer *) * rs_fec_enc->num_source_symbols, rs_fec_enc->adu_table);
	rs_fec_enc->adu_table = NULL;
}


static void gst_rs_fec_enc_alloc_fec_repair_packet_table(GstRSFECEnc *rs_fec_enc)
{
	g_assert(rs_fec_enc->fec_repair_packet_table == NULL);

	if (rs_fec_enc->num_repair_symbols == 0)
		return;

	GST_DEBUG_OBJECT(
		rs_fec_enc,
		"allocating FEC repair packet table  (num repair symbols: %u)",
		rs_fec_enc->num_repair_symbols
	);

	/* The FEC repair packet table is used during the source block
	 * processing. It is filled with GstBuffers that shall contain
	 * the built repair symbol data and the FEC payload ID. Once
	 * processing is done, the table will have no entries until
	 * the next source block processing. The only reason why this
	 * table would still be filled with packets after processing
	 * is when an error occurred. */
	rs_fec_enc->fec_repair_packet_table = g_slice_alloc0(sizeof(GstBuffer *) * rs_fec_enc->num_repair_symbols);
	/* This array contains GstMapInfo entries for each packet.
	 * When building symbols, OpenFEC needs access to the packet's
	 * memory. This is only available after mapping. So keep track
	 * of the map information to be able to  unmap after OpenFEC
	 * has finished building symbols. */
	rs_fec_enc->fec_repair_packet_map_infos = g_slice_alloc0(sizeof(GstMapInfo) * rs_fec_enc->num_repair_symbols);
}


static void gst_rs_fec_enc_free_fec_repair_packet_table(GstRSFECEnc *rs_fec_enc)
{
	if (rs_fec_enc->num_repair_symbols == 0)
		return;

	g_assert(rs_fec_enc->fec_repair_packet_table != NULL);
	/* It is assumed that any leftover FEC repair packets have been flushed at this point */
	g_assert(rs_fec_enc->cur_num_fec_repair_packets == 0);

	g_slice_free1(sizeof(GstBuffer *) * rs_fec_enc->num_repair_symbols, rs_fec_enc->fec_repair_packet_table);
	g_slice_free1(sizeof(GstBuffer *) * rs_fec_enc->num_repair_symbols, rs_fec_enc->fec_repair_packet_map_infos);

	rs_fec_enc->fec_repair_packet_table = NULL;
	rs_fec_enc->fec_repair_packet_map_infos = NULL;
}


static gboolean gst_rs_fec_enc_init_openfec(GstRSFECEnc *rs_fec_enc)
{
	of_status_t status;

	/* Catch redundant calls */
	if (rs_fec_enc->openfec_session != NULL)
		return TRUE;

	/* Create a new OpenFEC session, necessary for the actual encoding */
	if ((status = of_create_codec_instance(&(rs_fec_enc->openfec_session), OF_CODEC_REED_SOLOMON_GF_2_8_STABLE, OF_ENCODER, 0)) != OF_STATUS_OK)
	{
		GST_ERROR_OBJECT(rs_fec_enc, "could not create codec instance: %s", gst_rs_fec_enc_get_status_name(status));
		rs_fec_enc->openfec_session = NULL;
		CHECK_IF_FATAL_ERROR(rs_fec_enc, status);
		return FALSE;
	}

	/* NOTE: This element does not allow changes to the number of source/repair
	 * symbols once an OpenFEC session is open, so it is OK to allocate the tables
	 * once */

	/* Allocate tables here */
	gst_rs_fec_enc_alloc_encoding_symbol_table(rs_fec_enc);
	gst_rs_fec_enc_alloc_adu_table(rs_fec_enc);
	gst_rs_fec_enc_alloc_fec_repair_packet_table(rs_fec_enc);

	/* Reset to zero, to make sure future encoding length computations
	 * work correctly */
	rs_fec_enc->encoding_symbol_length = 0;

	GST_INFO_OBJECT(rs_fec_enc, "OpenFEC session initialized, session: %p", (gpointer)(rs_fec_enc->openfec_session));

	return TRUE;
}


static gboolean gst_rs_fec_enc_shutdown_openfec(GstRSFECEnc *rs_fec_enc)
{
	of_status_t status;

	/* Catch redundant calls */
	if (rs_fec_enc->openfec_session == NULL)
		return TRUE;

	/* No need to call gst_rs_fec_enc_flush() here, since it is
	 * called in the PAUSED->READY state change already */

	/* Deallocate the memory blocks of each symbol in the
	 * table, and the table itself */
	gst_rs_fec_enc_free_encoding_symbol_table(rs_fec_enc);

	/* Deallocate the other tables here */
	gst_rs_fec_enc_free_adu_table(rs_fec_enc);
	gst_rs_fec_enc_free_fec_repair_packet_table(rs_fec_enc);

	/* Set to zero, since all symbol memory blocks are deallocated now,
	 * and any new processing would require re-computing this length.
	 * anyway. It also helps with debugging. */
	rs_fec_enc->encoding_symbol_length = 0;

	/* Release the OpenFEC session */
	if ((status = of_release_codec_instance(rs_fec_enc->openfec_session)) != OF_STATUS_OK)
	{
		GST_ERROR_OBJECT(rs_fec_enc, "could not release codec instance: %s", gst_rs_fec_enc_get_status_name(status));
		CHECK_IF_FATAL_ERROR(rs_fec_enc, status);
		return FALSE;
	}

	/* All done */
	rs_fec_enc->openfec_session = NULL;
	GST_INFO_OBJECT(rs_fec_enc, "OpenFEC session shut down");

	return TRUE;
}


static gboolean gst_rs_fec_enc_configure_fec(GstRSFECEnc *rs_fec_enc, gsize encoding_symbol_length)
{
	/* Here, the encoder is (re)configured by sending new parameters to OpenFEC
	 * and (re)allocating the symbol memory blocks in the table. This is
	 * however only done if the encoding symbol length changed, otherwise
	 * the (re)configuration is unnecessary.
	 *
	 * NOTE: this means that num_source_symbols and num_repair_symbols remain
	 * constant; encoding_symbol_length is the only variable. Also see the
	 * checks in the PROP_NUM_SOURCE_SYMBOLS and PROP_NUM_REPAIR_SYMBOLS cases
	 * in the set_property() switch for more. */

	of_status_t status;
	of_rs_parameters_t params;
	guint i;

	if (rs_fec_enc->encoding_symbol_length == encoding_symbol_length)
	{
		GST_LOG_OBJECT(rs_fec_enc, "encoding symbol length did not change -> no need to (re)configure OpenFEC encoder");
		return TRUE;
	}

	GST_DEBUG_OBJECT(
		rs_fec_enc,
		"(re)configuring OpenFEC encoder  (num source symbols: %u  num repair symbols: %u  encoding symbol length: %" G_GSIZE_FORMAT ")",
		rs_fec_enc->num_source_symbols,
		rs_fec_enc->num_repair_symbols,
		encoding_symbol_length
	);

	memset(&params, 0, sizeof(params));
	params.nb_source_symbols = rs_fec_enc->num_source_symbols;
	params.nb_repair_symbols = rs_fec_enc->num_repair_symbols;
	params.encoding_symbol_length = encoding_symbol_length;

	/* Instruct the OpenFEC session to (re)configure itself */
	if ((status = of_set_fec_parameters(rs_fec_enc->openfec_session, (of_parameters_t *)(&params))) != OF_STATUS_OK)
	{
		GST_ERROR_OBJECT(rs_fec_enc, "could not set FEC parameters: %s", gst_rs_fec_enc_get_status_name(status));
		CHECK_IF_FATAL_ERROR(rs_fec_enc, status);
		return FALSE;
	}

	/* Deallocate any existing symbol memory blocks, but do NOT deallocate the
	 * table itself (unlike in gst_rs_fec_enc_free_encoding_symbol_table() ),
	 * since it is still needed. */
	if (rs_fec_enc->encoding_symbol_length != 0)
	{
		/* Deallocating the first num_source_symbols, NOT all
		 * num_encoding_symbols. See below for a reason why. */
		for (i = 0; i < rs_fec_enc->num_source_symbols; ++i)
			g_slice_free1(rs_fec_enc->encoding_symbol_length, rs_fec_enc->encoding_symbol_table[i]);
	}

	/* Allocate a new set of memory blocks with the new encoding symbol length each.
	 * Only allocate num_source_symbols, since the repair symbols are already
	 * allocated and stored in the fec_repair_packet_table. */
	for (i = 0; i < rs_fec_enc->num_source_symbols; ++i)
		rs_fec_enc->encoding_symbol_table[i] = g_slice_alloc(encoding_symbol_length);

	/* Set the new encoding symbol length */
	rs_fec_enc->encoding_symbol_length = encoding_symbol_length;

	return TRUE;
}


static void gst_rs_fec_enc_insert_adu(GstRSFECEnc *rs_fec_enc, GstBuffer *adu, guint esi)
{
	gsize adu_length;
	g_assert(adu != NULL);

	/* Get the length of the given ADU, and check if it is larger than the
	 * currently known maximum; if so, set it as the new maximum */
	adu_length = gst_buffer_get_size(adu);
	rs_fec_enc->cur_max_adu_length = MAX(adu_length, rs_fec_enc->cur_max_adu_length);

	rs_fec_enc->adu_table[esi] = adu;

	GST_LOG_OBJECT(
		rs_fec_enc,
		"ADU length: %" G_GSIZE_FORMAT " current max ADU length: %" G_GSIZE_FORMAT,
		adu_length,
		rs_fec_enc->cur_max_adu_length
	);
}


static GstFlowReturn gst_rs_fec_enc_push_adu(GstRSFECEnc *rs_fec_enc, GstBuffer *adu, guint esi)
{
	GstBuffer *fec_source_packet;
	GstMemory *wrapped_payload_id;
	GstFlowReturn ret;

	/* Incremental counter for source block nr */
	guint source_block_nr = rs_fec_enc->cur_source_block_nr;

	/* Just like the length field in the ADUI, the values in the
	 * payload ID use big endian */
	guint8 *fec_payload_id = g_slice_alloc(FEC_PAYLOAD_ID_LENGTH);

	/* source block number (24-bit value) */
	fec_payload_id[0] = ((source_block_nr & 0xFF0000) >> 16);
	fec_payload_id[1] = ((source_block_nr & 0x00FF00) >> 8);
	fec_payload_id[2] = ((source_block_nr & 0x0000FF) >> 0);
	/* encoding symbol ID (8-bit value) */
	fec_payload_id[3] = esi & 0xFF;
	/* source block length (16-bit value) */
	fec_payload_id[4] = ((rs_fec_enc->num_source_symbols & 0xFF00) >> 8);
	fec_payload_id[5] = ((rs_fec_enc->num_source_symbols & 0x00FF) >> 0);

	GST_LOG_OBJECT(rs_fec_enc, "pushing ADU from source block nr %u and with ESI %u as FEC source packet downstream", source_block_nr, esi);

	/* Create FEC source packet out of the ADU by appending the payload ID */
	fec_source_packet = adu;
	wrapped_payload_id = gst_memory_new_wrapped(
		0,
		fec_payload_id,
		FEC_PAYLOAD_ID_LENGTH,
		0,
		FEC_PAYLOAD_ID_LENGTH,
		fec_payload_id,
		gst_rs_fec_enc_free_payload_id
	);
	gst_buffer_append_memory(fec_source_packet, wrapped_payload_id);

	/* Clear timestamp and duration, since they are
	 * useless with FEC source packets
	 * (The source packet is a GstBuffer, which originally came
	 * from upstream, so it still has the timestamp and duration
	 * set by upstream) */
	GST_BUFFER_PTS(fec_source_packet) = GST_CLOCK_TIME_NONE;
	GST_BUFFER_DTS(fec_source_packet) = GST_CLOCK_TIME_NONE;
	GST_BUFFER_DURATION(fec_source_packet) = GST_CLOCK_TIME_NONE;

	/* Mark discontinuity at start */
	if (rs_fec_enc->first_source_packet)
	{
		GST_BUFFER_FLAG_SET(fec_source_packet, GST_BUFFER_FLAG_DISCONT);
		rs_fec_enc->first_source_packet = FALSE;
	}

	/* offset and offset_end have no meaning here */
	GST_BUFFER_OFFSET(fec_source_packet) = -1;
	GST_BUFFER_OFFSET_END(fec_source_packet) = -1;

	/* Send out the FEC source packet */
	ret = gst_pad_push(rs_fec_enc->fecsourcepad, fec_source_packet);

	if (ret != GST_FLOW_OK)
		GST_DEBUG_OBJECT(rs_fec_enc, "got return value %s while pushing", gst_flow_get_name(ret));

	return ret;
}


static void gst_rs_fec_enc_flush_all_adus(GstRSFECEnc *rs_fec_enc)
{
	/* If there are any leftover ADUs, unref them here,
	 * and set their entries in the ADU table to NULL. */

	guint esi;

	if (rs_fec_enc->cur_num_adus == 0)
		return;

	GST_LOG_OBJECT(rs_fec_enc, "flushing %u ADUs", rs_fec_enc->cur_num_adus);

	for (esi = 0; esi < rs_fec_enc->num_source_symbols; ++esi)
	{
		GstBuffer *adu = rs_fec_enc->adu_table[esi];
		rs_fec_enc->adu_table[esi] = NULL;
		if (adu != NULL)
			gst_buffer_unref(adu);
	}

	rs_fec_enc->cur_num_adus = 0;
}


static void gst_rs_fec_enc_flush_all_fec_repair_packets(GstRSFECEnc *rs_fec_enc)
{
	/* If there are any leftover FEC repair packets, unmap
	 * and unref them here, and set their entries in the
	 * table to NULL. */

	guint i;

	if (rs_fec_enc->cur_num_fec_repair_packets == 0)
		return;

	GST_LOG_OBJECT(rs_fec_enc, "flushing %u repair packets", rs_fec_enc->cur_num_fec_repair_packets);

	for (i = 0; i < rs_fec_enc->num_repair_symbols; ++i)
	{
		GstBuffer *fec_repair_packet = rs_fec_enc->fec_repair_packet_table[i];
		if (fec_repair_packet != NULL)
		{
			/* If a packet is still in the table, it implies the
			 * GstBuffer is still mapped, so unmap it first. */

			GstMapInfo *map_info = &(rs_fec_enc->fec_repair_packet_map_infos[i]);
			g_assert(map_info != NULL);
			gst_buffer_unmap(fec_repair_packet, map_info);

			gst_buffer_unref(fec_repair_packet);
		}
	}

	rs_fec_enc->cur_num_fec_repair_packets = 0;
}


static void gst_rs_fec_enc_free_payload_id(gpointer data)
{
	/* This function is called once a GstMemory block that
	 * contains a FEC payload ID is deallocated */
	g_slice_free1(FEC_PAYLOAD_ID_LENGTH, data);
}


static GstFlowReturn gst_rs_fec_enc_process_source_block(GstRSFECEnc *rs_fec_enc)
{
	GstBuffer *adu;
	guint i;
	GstFlowReturn ret = GST_FLOW_OK;

	/* Incremental counter for source block nr */
	guint source_block_nr = rs_fec_enc->cur_source_block_nr;

	/* Reed-Solomon and RFC 6865 both require encoding symbols to be of the same
	 * length for the same source block. encoding_symbol_length is that length. */
	gsize encoding_symbol_length;

	if (rs_fec_enc->cur_num_adus < rs_fec_enc->num_source_symbols)
	{
		GST_LOG_OBJECT(rs_fec_enc, "there are not enough ADUs yet to create a source block (present: %u required: %u) - skipping", rs_fec_enc->cur_num_adus, rs_fec_enc->num_source_symbols);
		return GST_FLOW_OK;
	}

	GST_LOG_OBJECT(rs_fec_enc, "there are enough ADUs to create a source block - processing source block #%u", source_block_nr);

	/* ADUIs are created by prepending 3 extra bytes to ADUs according to RFC 6865
	 * these byates contain ADU flow identification and ADU length (in big endian)
	 * Since ADUIs and repair symbol must be of the same size, the length of the longest
	 * ADU+ the 3 bytes is considered the "encoding symbol length" */
	encoding_symbol_length = 1 + 2 + rs_fec_enc->cur_max_adu_length;
	GST_LOG_OBJECT(rs_fec_enc, "using encoding symbol length of %" G_GSIZE_FORMAT " bytes for this source block", encoding_symbol_length);

	/* In this block, the encoder is (re)configured and ADUs are fed into the encoder.
	 * None of these steps make any sense if num_source_symbols is 0, since then, no
	 * repair data shall be generated at all. */
	if (rs_fec_enc->num_repair_symbols > 0)
	{
		/* Request encoder reconfiguration. The function takes care of checking if
		 * a reconfiguration is really necessary (it is if the encoding symbol length
		 * changed since last time). */
		if (!gst_rs_fec_enc_configure_fec(rs_fec_enc, encoding_symbol_length))
		{
			GST_ERROR_OBJECT(rs_fec_enc, "reconfiguring failed");
			ret = GST_FLOW_ERROR;
			goto cleanup;
		}

		/* Convert ADUs into ADUIs, and put them into the encoding symbol table for the
		 * OpenFEC Reed-Solomon encoder */
		for (i = 0; i < rs_fec_enc->num_source_symbols; ++i)
		{
			guint8 *adui_memblock;
			gsize padding;
			gsize adu_length;
			guint adu_flow_id = 0; /* XXX: Currently, only one flow (flow 0) is supported */

			/* Get the ADU from the table. Since the ADU will not
			 * be needed in the table anymore, set its entry to NULL.
			 * It is pushed downstream, so no need to unref it either. */
			g_assert(rs_fec_enc->cur_num_adus > 0);
			adu = rs_fec_enc->adu_table[i];
			adu_length = gst_buffer_get_size(adu);
			rs_fec_enc->adu_table[i] = NULL;
			rs_fec_enc->cur_num_adus--;

			g_assert((adu_length + 3) <= encoding_symbol_length);

			/* Get the corresponding entry from the symbol table */
			adui_memblock = rs_fec_enc->encoding_symbol_table[i];

			/* Prepend the extra 3 bytes to the ADU and add padding,
			 * converting it into an ADUI */
			/* ADU flow ID, one byte */
			adui_memblock[0] = adu_flow_id;
			/* Length of ADU, 16-bit big endian unsigned integer */
			adui_memblock[1] = (adu_length & 0xFF00) >> 8;
			adui_memblock[2] = (adu_length & 0x00FF);
			/* The ADU itself */
			gst_buffer_extract(adu, 0, adui_memblock + 3, adu_length);
			/* Padding in case this ADU is not the longest one */
			padding = rs_fec_enc->cur_max_adu_length - adu_length;
			if (padding > 0)
				memset(adui_memblock + 3 + adu_length, 0, padding);

			/* ADU is not needed anymore, discard */
			gst_buffer_unref(adu);

			GST_LOG_OBJECT(rs_fec_enc, "preparing ADU #%u in source block for encoder:  flow ID: %u  length: %" G_GSIZE_FORMAT " bytes  padding: %" G_GSIZE_FORMAT " bytes", i, adu_flow_id, adu_length, padding);
		}
	}

	/* Push STREAM_START, CAPS, SEGMENT events if necessary */
	if (!rs_fec_enc->segment_started)
	{
		GstEvent *event;
		GstCaps *caps;
		GstSegment segment;
		gchar *stream_id;
		guint group_id;

		group_id = gst_util_group_id_next();
		gst_segment_init(&segment, GST_FORMAT_BYTES);

		if (rs_fec_enc->stream_started)
			GST_DEBUG_OBJECT(rs_fec_enc, "pushing SEGMENT and CAPS events downstream");
		else
			GST_DEBUG_OBJECT(rs_fec_enc, "pushing STREAM_START, SEGMENT, and CAPS events downstream (stream-start group id: %u)", group_id);

		/* push stream start, caps, segment events for source pad */
		{
			if (!rs_fec_enc->stream_started)
			{
				/* stream start */
				stream_id = gst_pad_create_stream_id(rs_fec_enc->fecsourcepad, GST_ELEMENT_CAST(rs_fec_enc), "fecsource");
				event = gst_event_new_stream_start(stream_id);
				gst_event_set_group_id(event, group_id);
				gst_pad_push_event(rs_fec_enc->fecsourcepad, event);
				g_free(stream_id);

				/* caps */
				caps = gst_caps_from_string(FEC_SOURCE_CAPS_STR);
				event = gst_event_new_caps(caps);
				gst_pad_push_event(rs_fec_enc->fecsourcepad, event);
				gst_caps_unref(caps);
			}

			/* segment */
			event = gst_event_new_segment(&segment);
			gst_pad_push_event(rs_fec_enc->fecsourcepad, event);
		}

		/* push stream start, caps, segment events for repair pad */
		{
			if (!rs_fec_enc->stream_started)
			{
				/* stream start */
				stream_id = gst_pad_create_stream_id(rs_fec_enc->fecrepairpad, GST_ELEMENT_CAST(rs_fec_enc), "fecrepair");
				event = gst_event_new_stream_start(stream_id);
				gst_event_set_group_id(event, group_id);
				gst_pad_push_event(rs_fec_enc->fecrepairpad, event);
				g_free(stream_id);

				/* caps */
				caps = gst_caps_from_string(FEC_REPAIR_CAPS_STR);
				event = gst_event_new_caps(caps);
				gst_pad_push_event(rs_fec_enc->fecrepairpad, event);
				gst_caps_unref(caps);
			}

			/* segment */
			event = gst_event_new_segment(&segment);
			gst_pad_push_event(rs_fec_enc->fecrepairpad, event);
		}

		rs_fec_enc->segment_started = TRUE;
		rs_fec_enc->stream_started = TRUE;
	}

	/* Allocate buffers for the FEC repair packets */
	for (i = 0; i < rs_fec_enc->num_repair_symbols; ++i)
	{
		GstBuffer *fec_repair_packet;
		GstMapInfo *map_info;

		/* Allocate buffer for the packet, and put it in the table */
		fec_repair_packet = gst_buffer_new_allocate(NULL, encoding_symbol_length + 6, NULL);
		rs_fec_enc->fec_repair_packet_table[i] = fec_repair_packet;

		/* Retrieve corresponding map info value that shall be filled
		 * with mapping information */
		map_info = &(rs_fec_enc->fec_repair_packet_map_infos[i]);

		/* Map the buffer. It will be unmapped later, either when a
		 * repair packet has been fully constructed, or when
		 * gst_rs_fec_enc_flush_all_fec_repair_packets() is called. */
		gst_buffer_map(fec_repair_packet, map_info, GST_MAP_WRITE);

		/* Store the pointer to the region in the mapped buffer data block
		 * where the encoding symbol shall be constructed and stored.
		 * The first 6 bytes are reserved for the FEC payload ID, so
		 * apply an offset. */
		rs_fec_enc->encoding_symbol_table[rs_fec_enc->num_source_symbols + i] = map_info->data + 6;
	}
	/* Update the counter */
	rs_fec_enc->cur_num_fec_repair_packets = rs_fec_enc->num_repair_symbols;

	/* Build repair symbols and send them out as FEC repair packets */
	for (i = 0; i < rs_fec_enc->num_repair_symbols; ++i)
	{
		guint esi = i + rs_fec_enc->num_source_symbols; /* ESI = encoding symbol ID */
		GstBuffer *fec_repair_packet = rs_fec_enc->fec_repair_packet_table[i];
		GstMapInfo *map_info = &(rs_fec_enc->fec_repair_packet_map_infos[i]);
		of_status_t status;

		/* Build this repair symbol */
		if ((status = of_build_repair_symbol(rs_fec_enc->openfec_session, rs_fec_enc->encoding_symbol_table, esi)) != OF_STATUS_OK)
		{
			GST_ERROR_OBJECT(rs_fec_enc, "could not build repair symbol #%u: %s", i, gst_rs_fec_enc_get_status_name(status));
			CHECK_IF_FATAL_ERROR(rs_fec_enc, status);
			ret = GST_FLOW_ERROR;
			goto cleanup;
		}
		else
			GST_LOG_OBJECT(rs_fec_enc, "built repair symbol #%u", i);

		/* Build the FEC payload ID */

		/* Just like the length field in the ADUI, the values in the
		 * payload ID use big endian */
		guint8 *fec_payload_id = map_info->data;
		/* source block number (24-bit value) */
		fec_payload_id[0] = ((source_block_nr & 0xFF0000) >> 16);
		fec_payload_id[1] = ((source_block_nr & 0x00FF00) >> 8);
		fec_payload_id[2] = ((source_block_nr & 0x0000FF) >> 0);
		/* encoding symbol ID (8-bit value) */
		fec_payload_id[3] = esi & 0xFF;
		/* source block length (16-bit value) */
		fec_payload_id[4] = ((rs_fec_enc->num_source_symbols & 0xFF00) >> 8);
		fec_payload_id[5] = ((rs_fec_enc->num_source_symbols & 0x00FF) >> 0);

		GST_LOG_OBJECT(rs_fec_enc, "pushing FEC repair packet:  source block nr: %u  ESI: %u", source_block_nr, esi);

		/* No more write access is needed, so unmap the buffer */
		gst_buffer_unmap(fec_repair_packet, map_info);

		/* This FEC repair packet is finished and ready to be pushed
		 * downstream. Remove it from the table, and decrement the
		 * cur_num_fec_repair_packets counter. */
		rs_fec_enc->fec_repair_packet_table[i] = NULL;
		g_assert(rs_fec_enc->cur_num_fec_repair_packets > 0);
		rs_fec_enc->cur_num_fec_repair_packets--;

		/* Mark discontinuity at start */
		if (rs_fec_enc->first_repair_packet)
		{
			GST_BUFFER_FLAG_SET(fec_repair_packet, GST_BUFFER_FLAG_DISCONT);
			rs_fec_enc->first_repair_packet = FALSE;
		}

		/* offset and offset_end have no meaning here */
		GST_BUFFER_OFFSET(fec_repair_packet) = -1;
		GST_BUFFER_OFFSET_END(fec_repair_packet) = -1;

		/* Send out the FEC repair packet */
		if ((ret = gst_pad_push(rs_fec_enc->fecrepairpad, fec_repair_packet)) != GST_FLOW_OK)
			goto cleanup;
	}

	GST_LOG_OBJECT(rs_fec_enc, "finished processing source block #%u", source_block_nr);

	/* After successfully processing this
	 * source block, increase number */
	rs_fec_enc->cur_source_block_nr++;

cleanup:
	/* Cleanup any leftover data in case an error occurred
	 * and not all ADUs and/or repair packets were processed above */
	gst_rs_fec_enc_flush_all_adus(rs_fec_enc);
	gst_rs_fec_enc_flush_all_fec_repair_packets(rs_fec_enc);
	rs_fec_enc->cur_max_adu_length = 0;

	return ret;
}


static void gst_rs_fec_enc_reset_states(GstRSFECEnc *rs_fec_enc)
{
	/* _Not_ setting encoding_symbol_length to 0 here, since its
	 * size also defines the size of the symbol memory blocks.
	 * These shall only be reallocated if the encoding_symbol_length
	 * changes. If encoding_symbol_length is set to 0 here, it means
	 * the memory blocks would have to be deallocated here as
	 * well, which is a waste if future incoming blocks happen to
	 * have the same encoding symbol length as the past ones. */

	rs_fec_enc->cur_max_adu_length = 0;
	rs_fec_enc->first_source_packet = TRUE;
	rs_fec_enc->first_repair_packet = TRUE;
	rs_fec_enc->segment_started = FALSE;
	rs_fec_enc->eos_received = FALSE;
}


static void gst_rs_fec_enc_flush(GstRSFECEnc *rs_fec_enc)
{
	gst_rs_fec_enc_flush_all_adus(rs_fec_enc);
	gst_rs_fec_enc_flush_all_fec_repair_packets(rs_fec_enc);
	gst_rs_fec_enc_reset_states(rs_fec_enc);
}


static gchar const * gst_rs_fec_enc_get_status_name(of_status_t status)
{
	switch (status)
	{
		case OF_STATUS_OK: return "ok";
		case OF_STATUS_FAILURE: return "failure";
		case OF_STATUS_ERROR: return "error";
		case OF_STATUS_FATAL_ERROR: return "fatal error";
		default: return "<unknown>";
	}
}
