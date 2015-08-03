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
 * GstRSFECEnc is a decoder element that implements RFC 6865 for application-
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
 * The decoder works by keeping a "source block table". This hash table uses
 * source block numbers as keys, and pointers to corresponding source blocks
 * as values. When a FEC source or repair packet is received, its source
 * block number is received from its FEC payload ID. The appropriate source
 * block is then retrieved from the table (if no such source block exists, it
 * is created and inserted into the table). Then, the FEC packet is added to
 * the source block. In case of the FEC source packets, the ADUs inside are
 * also immediately extracted and inserted in the source block's output_adu_table.
 *
 * A source block is considered incomplete unless enough encoding symbols which
 * belong to it have been received. At least k encoding symbols must have been
 * received in order for OpenFEC to be able to recover any lost symbols. In the
 * special case that these k symbols are all source symbols (implying that no
 * repair symbols are present), the decoder just marks the source block as
 * complete. Otherwise, it instructs OpenFEC to recover any lost symbols, and
 * marks the source block as complete. Either way, afterwards, all ADUs from this
 * source blocks are available.
 *
 * Since there is a chance that entire source blocks come in out-of-order, they
 * are not pushed downstream immediately, even if they are complete. Instead,
 * they are retained in the source block table. However, the decoder does
 * perform "pruning" when new packets are received. The packet's source block
 * number is compared against a reference (most_recent_block_nr). If the packet's
 * number is "newer", most_recent_block_nr is set to this value, and pruning
 * is performed.
 *
 * "Pruning" means that all source blocks in the hash table are checked. If their
 * source block numbers are "too old" compared to the new most_recent_block_nr,
 * they are "pruned"; they get removed from the hash table, and placed in a
 * temporary list. This list is then sorted according to the block numbers,
 * and the source blocks in this list are then finally pushed downstream.
 * This ensures source blocks are pushed downstream in order.
 *
 * If however sorting is disabled (by setting the "sort-output" property to FALSE),
 * then the decoder operates differently. Received ADUs are pushed downstream
 * immediately. Also, once a source block can be processed, any recovered ADUs
 * are also pushed downstream immediately, and the source block is destroyed right
 * afterwards. Pruning still happens, but it is reduced to cleaning up incomplete
 * source blocks (no ADUs are pushed while pruning, since they got pushed already).
 *
 * Source block numbers can be "newer" and "too old". This notion of age refers to
 * the distance between block numbers. If for example most_recent_block_nr is
 * 5, and the source block number of a FEC packet is 4, then it is a bit older
 * (distance 1). If the number is 6, it is newer (again, distance 1). If the distance
 * is larger than max_source_block_age, the number is considered to be "too old".
 * This check wraps around the 2^24 range of source block numbers. If for example
 * max_source_block_age is 2, and most_recent_block_nr is 0, it means that source
 * block numbers 0 and 16777215 are OK, but 16777214 is too old, and 1 is newer.
 * Anything from (most_recent_block_nr+1) to (most_recent_block_nr+2^22)%(2^22) is
 * considered newer than most_recent_block_nr.
 *
 * This mechanism implies that max_source_block_age has an influence on the decoder's
 * latency, just as num_source_symbols has. Too large values mean that the latency
 * can become large as well.
 */


/* NOTE: Currently, only GF(2^8) Reed-Solomon is supported. RFC 6865 however also
 * mentions support for GF(2^m), where 2 <= m <= 16. OpenFEC currently does not support
 * GF(2^m) unless m is 4 or 8. Therefore, only GF(2^8) is supported in this element
 * for now. Once OpenFEC has been extended to support the necessary range for m,
 * reevaluate. */


#include <stdlib.h>
#include <string.h>
#include "gstrsfecdec.h"


GST_DEBUG_CATEGORY(rs_fec_dec_debug);
#define GST_CAT_DEFAULT rs_fec_dec_debug


enum
{
	PROP_0,
	PROP_NUM_SOURCE_SYMBOLS,
	PROP_NUM_REPAIR_SYMBOLS,
	PROP_MAX_SOURCE_BLOCK_AGE,
	PROP_DO_TIMESTAMP,
	PROP_SORT_OUTPUT
};


typedef struct
{
	/* Number of this source block */
	guint block_nr;

	/* Bitmask for identifying which packets are present.
	 * 1 = FEC source/repair packet present. 0 = missing.
	 * The bit number corresponds to the ESI of the packet.
	 * 8 64-bit integers, since the maximum number of encoding
	 * symbols is 255. */
	/* NOTE: the limit is 255 if m=8, since with Reed-Solomon,
	 * up to 2^m - 1 encoding symbols can be used. If m != 8,
	 * the limit won't be 255 ! (See the top of this file.) */
	guint64 packet_mask[8];

	/* Lists containing received source and repair packets.
	 * the entries are _not_ ordered according to the packet ESIs,
	 * since ordering is done implicitely later during the
	 * source block processing. */
	GSList *source_packets, *repair_packets;
	/* How many source and repair packets are currently contained
	 * in the lists. */
	guint num_source_packets, num_repair_packets;

	/* Table holding the GstBuffers of the ADUs that will be
	 * pushed downstream when this source block is pruned. */
	GstBuffer **output_adu_table;

	/* If TRUE, then this source block has been processed,
	 * all lost ADUs have been recovered and are placed in the
	 * output_adu_table, and it is considered a "complete" source
	 * block. A source block which does not have all of its ADUs
	 * in the output_adu_table yet is considered incomplete. */
	gboolean is_complete;
}
GstRSFECDecSourceBlock;


#define DEFAULT_NUM_SOURCE_SYMBOLS 4
#define DEFAULT_NUM_REPAIR_SYMBOLS 2
#define DEFAULT_MAX_SOURCE_BLOCK_AGE 1
#define DEFAULT_DO_TIMESTAMP TRUE
#define DEFAULT_SORT_OUTPUT TRUE


#define FEC_SOURCE_CAPS_STR "application/x-fec-source-flow, encoding-id = (int) 8"
#define FEC_REPAIR_CAPS_STR "application/x-fec-repair-flow, encoding-id = (int) 8"


#define SOURCE_BLOCK_SET_FLAG(SRCBLOCK, IDX) \
	do { \
		(SRCBLOCK)->packet_mask[(IDX) >> 6] |= ((guint64)1) << ((IDX) & 63); \
	} while (0)

#define SOURCE_BLOCK_UNSET_FLAG(SRCBLOCK, IDX) \
	do { \
		(SRCBLOCK)->packet_mask[(IDX) >> 6] &= ~(((guint64)1) << ((IDX) & 63)); \
	} while (0)

#define SOURCE_BLOCK_IS_FLAG_SET(SRCBLOCK, IDX) \
	((((SRCBLOCK)->packet_mask[(IDX) >> 6]) & (((guint64)1) << ((IDX) & 63))) != 0)


#define CHECK_IF_FATAL_ERROR(elem, status) \
	do { \
		if ((status) == OF_STATUS_FATAL_ERROR) \
			GST_ELEMENT_ERROR((elem), LIBRARY, FAILED, ("OpenFEC reports fatal error"), (NULL)); \
	} while (0)


#define RS_LOCK_MUTEX(obj) do { g_mutex_lock(&(((GstRSFECDec *)(obj))->mutex)); } while (0)
#define RS_UNLOCK_MUTEX(obj) do { g_mutex_unlock(&(((GstRSFECDec *)(obj))->mutex)); } while (0)


static GstStaticPadTemplate static_fecsource_template = GST_STATIC_PAD_TEMPLATE(
	"fecsource",
	GST_PAD_SINK,
	GST_PAD_ALWAYS,
	GST_STATIC_CAPS(FEC_SOURCE_CAPS_STR)
);


static GstStaticPadTemplate static_fecrepair_template = GST_STATIC_PAD_TEMPLATE(
	"fecrepair",
	GST_PAD_SINK,
	GST_PAD_ALWAYS,
	GST_STATIC_CAPS(FEC_REPAIR_CAPS_STR)
);


static GstStaticPadTemplate static_src_template = GST_STATIC_PAD_TEMPLATE(
	"src",
	GST_PAD_SRC,
	GST_PAD_ALWAYS,
	GST_STATIC_CAPS_ANY
);




G_DEFINE_TYPE(GstRSFECDec, gst_rs_fec_dec, GST_TYPE_ELEMENT)


static void gst_rs_fec_dec_finalize(GObject *object);
static void gst_rs_fec_dec_set_property(GObject *object, guint prop_id, GValue const *value, GParamSpec *pspec);
static void gst_rs_fec_dec_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);

static GstStateChangeReturn gst_rs_fec_dec_change_state(GstElement *element, GstStateChange transition);

static gboolean gst_rs_fec_dec_fecsource_event(GstPad *pad, GstObject *parent, GstEvent *event);
static gboolean gst_rs_fec_dec_fecrepair_event(GstPad *pad, GstObject *parent, GstEvent *event);
static GstFlowReturn gst_rs_fec_dec_fecsource_chain(GstPad *pad, GstObject *parent, GstBuffer *buffer);
static GstFlowReturn gst_rs_fec_dec_fecrepair_chain(GstPad *pad, GstObject *parent, GstBuffer *buffer);

static void gst_rs_fec_dec_alloc_encoding_symbol_table(GstRSFECDec *rs_fec_dec);
static void gst_rs_fec_dec_free_encoding_symbol_table(GstRSFECDec *rs_fec_dec);

static void gst_rs_fec_dec_source_packet_read_payload_id(GstBuffer *fec_source_packet, guint *source_block_nr, guint *esi);
static void gst_rs_fec_dec_repair_packet_read_payload_id(GstBuffer *fec_repair_packet, guint *source_block_nr, guint *esi);

static GstFlowReturn gst_rs_fec_dec_insert_fec_packet(GstRSFECDec *rs_fec_dec, GstBuffer *fec_packet, gboolean is_source_packet);

static GstRSFECDecSourceBlock* gst_rs_fec_dec_fetch_source_block(GstRSFECDec *rs_fec_dec, guint block_nr);
static GstRSFECDecSourceBlock* gst_rs_fec_dec_create_source_block(GstRSFECDec *rs_fec_dec, guint block_nr);
static void gst_rs_fec_dec_destroy_source_block(GstRSFECDec *rs_fec_dec, GstRSFECDecSourceBlock *source_block);
static gboolean gst_rs_fec_dec_can_source_block_be_processed(GstRSFECDec *rs_fec_dec, GstRSFECDecSourceBlock *source_block);
static GstFlowReturn gst_rs_fec_dec_process_source_block(GstRSFECDec *rs_fec_dec, GstRSFECDecSourceBlock *source_block);
static GstFlowReturn gst_rs_fec_dec_push_source_block(GstRSFECDec *rs_fec_dec, GstRSFECDecSourceBlock *source_block);

static gboolean gst_rs_fec_dec_is_source_block_nr_newer(guint candidate_block_nr, guint reference_block_nr);
static gboolean gst_rs_fec_dec_is_source_block_nr_recent_enough(guint candidate_block_nr, guint reference_block_nr, guint max_age);
static gboolean gst_rs_fec_dec_check_if_source_block_in_range(guint block_nr, guint start, guint end);
static gint gst_rs_fec_dec_compare_source_blocks(gconstpointer first, gconstpointer second);

static GstFlowReturn gst_rs_fec_dec_prune_source_block_table(GstRSFECDec *rs_fec_dec, guint source_block_nr);
static GstFlowReturn gst_rs_fec_dec_drain_source_block_table(GstRSFECDec *rs_fec_dec);

static void gst_rs_fec_dec_reset_states(GstRSFECDec *rs_fec_dec);
static void gst_rs_fec_dec_flush(GstRSFECDec *rs_fec_dec);
static GstFlowReturn gst_rs_fec_dec_push_adu(GstRSFECDec *rs_fec_dec, GstBuffer *adu);
static void gst_rs_fec_dec_push_stream_start(GstRSFECDec *rs_fec_dec);
static void gst_rs_fec_dec_push_segment(GstRSFECDec *rs_fec_dec);
static void gst_rs_fec_dec_push_eos(GstRSFECDec *rs_fec_dec);
static of_session_t* gst_rs_fec_dec_create_openfec_session(GstRSFECDec *rs_fec_dec, gsize encoding_symbol_length);
static void* gst_rs_fec_dec_openfec_source_symbol_cb(void *context, UINT32 size, UINT32 esi);
static gchar const * gst_rs_fec_dec_get_status_name(of_status_t status);



static void gst_rs_fec_dec_class_init(GstRSFECDecClass *klass)
{
	GObjectClass *object_class;
	GstElementClass *element_class;

	GST_DEBUG_CATEGORY_INIT(rs_fec_dec_debug, "rsfecdec", 0, "FECFRAME RFC 6865 Reed-Solomon scheme decoder");

	object_class = G_OBJECT_CLASS(klass);
	element_class = GST_ELEMENT_CLASS(klass);

	gst_element_class_add_pad_template(element_class, gst_static_pad_template_get(&static_fecsource_template));
	gst_element_class_add_pad_template(element_class, gst_static_pad_template_get(&static_fecrepair_template));
	gst_element_class_add_pad_template(element_class, gst_static_pad_template_get(&static_src_template));

	object_class->finalize      = GST_DEBUG_FUNCPTR(gst_rs_fec_dec_finalize);
	object_class->set_property  = GST_DEBUG_FUNCPTR(gst_rs_fec_dec_set_property);
	object_class->get_property  = GST_DEBUG_FUNCPTR(gst_rs_fec_dec_get_property);

	element_class->change_state = GST_DEBUG_FUNCPTR(gst_rs_fec_dec_change_state);

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
			"How many repair symbols to use per Reed-Solomon repair block (0 disables FEC repair)",
			0, G_MAXUINT,
			DEFAULT_NUM_REPAIR_SYMBOLS,
			G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS
		)
	);
	g_object_class_install_property(
		object_class,
		PROP_MAX_SOURCE_BLOCK_AGE,
		g_param_spec_uint(
			"max-source-block-age",
			"Max source block age",
			"How old a source block can be before it is evicted from the hash table and pushed downstream",
			1, G_MAXUINT,
			DEFAULT_MAX_SOURCE_BLOCK_AGE,
			G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS
		)
	);
	g_object_class_install_property(
		object_class,
		PROP_DO_TIMESTAMP,
		g_param_spec_boolean(
			"do-timestamp",
			"Do timestamping",
			"Apply the current running time to outgoing ADUs",
			DEFAULT_DO_TIMESTAMP,
			G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS
		)
	);
	g_object_class_install_property(
		object_class,
		PROP_SORT_OUTPUT,
		g_param_spec_boolean(
			"sort-output",
			"Sort output",
			"Sort outgoing ADUs by source block number and ESI",
			DEFAULT_SORT_OUTPUT,
			G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS
		)
	);

	gst_element_class_set_static_metadata(
		element_class,
		"Reed-Solomon forward error correction decoder",
		"Codec/Decoder/Network",
		"Decoder for forward-error erasure coding based on the FECFRAME Reed-Solomon scheme RFC 6865",
		"Carlos Rafael Giani <dv@pseudoterminal.org>"
	);
}


static void gst_rs_fec_dec_init(GstRSFECDec *rs_fec_dec)
{
	rs_fec_dec->num_source_symbols = DEFAULT_NUM_SOURCE_SYMBOLS;
	rs_fec_dec->num_repair_symbols = DEFAULT_NUM_REPAIR_SYMBOLS;
	rs_fec_dec->num_encoding_symbols = rs_fec_dec->num_source_symbols + rs_fec_dec->num_repair_symbols;

	rs_fec_dec->max_source_block_age = DEFAULT_MAX_SOURCE_BLOCK_AGE;

	rs_fec_dec->do_timestamp = DEFAULT_DO_TIMESTAMP;

	rs_fec_dec->first_adu = TRUE;

	rs_fec_dec->encoding_symbol_length = 0;

	rs_fec_dec->sort_output = DEFAULT_SORT_OUTPUT;

	rs_fec_dec->allocated_encoding_symbol_table = NULL;
	rs_fec_dec->received_encoding_symbol_table = NULL;
	rs_fec_dec->recovered_encoding_symbol_table = NULL;

	rs_fec_dec->fec_repair_packet_mapinfos = NULL;

	rs_fec_dec->source_block_table = g_hash_table_new(g_direct_hash, g_direct_equal);
	rs_fec_dec->first_pruning = TRUE;
	rs_fec_dec->most_recent_block_nr = 0;

	g_mutex_init(&(rs_fec_dec->mutex));

	rs_fec_dec->segment_started = FALSE;
	rs_fec_dec->stream_started = FALSE;
	rs_fec_dec->fecsource_eos = FALSE;
	rs_fec_dec->fecrepair_eos = FALSE;

	rs_fec_dec->fecsourcepad = gst_ghost_pad_new_no_target_from_template(
		"fecsource",
		gst_element_class_get_pad_template(GST_ELEMENT_GET_CLASS(rs_fec_dec), "fecsource")
	);
	gst_element_add_pad(GST_ELEMENT(rs_fec_dec), rs_fec_dec->fecsourcepad);

	rs_fec_dec->fecrepairpad = gst_ghost_pad_new_no_target_from_template(
		"fecrepair",
		gst_element_class_get_pad_template(GST_ELEMENT_GET_CLASS(rs_fec_dec), "fecrepair")
	);
	gst_element_add_pad(GST_ELEMENT(rs_fec_dec), rs_fec_dec->fecrepairpad);

	rs_fec_dec->srcpad = gst_ghost_pad_new_no_target_from_template(
		"src",
		gst_element_class_get_pad_template(GST_ELEMENT_GET_CLASS(rs_fec_dec), "src")
	);
	gst_element_add_pad(GST_ELEMENT(rs_fec_dec), rs_fec_dec->srcpad);

	gst_pad_set_event_function(rs_fec_dec->fecsourcepad, GST_DEBUG_FUNCPTR(gst_rs_fec_dec_fecsource_event));
	gst_pad_set_event_function(rs_fec_dec->fecrepairpad, GST_DEBUG_FUNCPTR(gst_rs_fec_dec_fecrepair_event));

	gst_pad_set_chain_function(rs_fec_dec->fecsourcepad, GST_DEBUG_FUNCPTR(gst_rs_fec_dec_fecsource_chain));
	gst_pad_set_chain_function(rs_fec_dec->fecrepairpad, GST_DEBUG_FUNCPTR(gst_rs_fec_dec_fecrepair_chain));
}


static void gst_rs_fec_dec_finalize(GObject *object)
{
	GstRSFECDec *rs_fec_dec = GST_RS_FEC_DEC(object);

	g_hash_table_unref(rs_fec_dec->source_block_table);
	g_mutex_clear(&(rs_fec_dec->mutex));

	G_OBJECT_CLASS(gst_rs_fec_dec_parent_class)->finalize(object);
}


static void gst_rs_fec_dec_set_property(GObject *object, guint prop_id, GValue const *value, GParamSpec *pspec)
{
	GstRSFECDec *rs_fec_dec = GST_RS_FEC_DEC(object);

	/* NOTE: this assumes Reed-Solomon with GF(2^8) is used
	 * once OpenFEC can handle GF(2^m) with 2 <= m <= 16,
	 * replace this constant with something appropriate */
	guint const max_num_encoding_symbols = (1 << 8) - 1;

	switch (prop_id)
	{
		case PROP_NUM_SOURCE_SYMBOLS:
			GST_OBJECT_LOCK(object);
			if (rs_fec_dec->allocated_encoding_symbol_table == NULL)
			{
				rs_fec_dec->num_source_symbols = g_value_get_uint(value);
				rs_fec_dec->num_encoding_symbols = rs_fec_dec->num_source_symbols + rs_fec_dec->num_repair_symbols;
				if (rs_fec_dec->num_encoding_symbols > max_num_encoding_symbols)
				{
					GST_ELEMENT_ERROR(
						object, LIBRARY, SETTINGS,
						("invalid total number of encoding symbols"),
						("number of source symbols: %u  repair symbols: %u  source+repair: %u  maximum allowed: %u", rs_fec_dec->num_source_symbols, rs_fec_dec->num_repair_symbols, rs_fec_dec->num_encoding_symbols, max_num_encoding_symbols)
					);
				}
			}
			else
				GST_ELEMENT_WARNING(object, LIBRARY, SETTINGS, ("cannot set number of source symbols after initializing decoder"), (NULL));
			GST_OBJECT_UNLOCK(object);
			break;

		case PROP_NUM_REPAIR_SYMBOLS:
			GST_OBJECT_LOCK(object);
			if (rs_fec_dec->allocated_encoding_symbol_table == NULL)
			{
				rs_fec_dec->num_repair_symbols = g_value_get_uint(value);
				rs_fec_dec->num_encoding_symbols = rs_fec_dec->num_source_symbols + rs_fec_dec->num_repair_symbols;
				if (rs_fec_dec->num_encoding_symbols > max_num_encoding_symbols)
				{
					GST_ELEMENT_ERROR(
						object, LIBRARY, SETTINGS,
						("invalid total number of encoding symbols"),
						("number of source symbols: %u  repair symbols: %u  source+repair: %u  maximum allowed: %u", rs_fec_dec->num_source_symbols, rs_fec_dec->num_repair_symbols, rs_fec_dec->num_encoding_symbols, max_num_encoding_symbols)
					);
				}
			}
			else
				GST_ELEMENT_WARNING(object, LIBRARY, SETTINGS, ("cannot set number of repair symbols after initializing decoder"), (NULL));
			GST_OBJECT_UNLOCK(object);
			break;

		case PROP_MAX_SOURCE_BLOCK_AGE:
			GST_OBJECT_LOCK(object);
			if (rs_fec_dec->allocated_encoding_symbol_table == NULL)
				rs_fec_dec->max_source_block_age = g_value_get_uint(value);
			else
				GST_ELEMENT_WARNING(object, LIBRARY, SETTINGS, ("cannot set maximum source block age after initializing decoder"), (NULL));
			GST_OBJECT_UNLOCK(object);
			break;

		case PROP_DO_TIMESTAMP:
			GST_OBJECT_LOCK(object);
			rs_fec_dec->do_timestamp = g_value_get_boolean(value);
			GST_OBJECT_UNLOCK(object);
			break;

		case PROP_SORT_OUTPUT:
			GST_OBJECT_LOCK(object);
			rs_fec_dec->sort_output = g_value_get_boolean(value);
			GST_OBJECT_UNLOCK(object);
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}


static void gst_rs_fec_dec_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	GstRSFECDec *rs_fec_dec = GST_RS_FEC_DEC(object);

	switch (prop_id)
	{
		case PROP_NUM_SOURCE_SYMBOLS:
			g_value_set_uint(value, rs_fec_dec->num_source_symbols);
			break;

		case PROP_NUM_REPAIR_SYMBOLS:
			g_value_set_uint(value, rs_fec_dec->num_repair_symbols);
			break;

		case PROP_MAX_SOURCE_BLOCK_AGE:
			g_value_set_uint(value, rs_fec_dec->max_source_block_age);
			break;

		case PROP_DO_TIMESTAMP:
			g_value_set_boolean(value, rs_fec_dec->do_timestamp);
			break;

		case PROP_SORT_OUTPUT:
			g_value_set_boolean(value, rs_fec_dec->sort_output);
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}


static GstStateChangeReturn gst_rs_fec_dec_change_state(GstElement *element, GstStateChange transition)
{
	GstRSFECDec *rs_fec_dec = GST_RS_FEC_DEC(element);
	GstStateChangeReturn result;

	switch (transition)
	{
		case GST_STATE_CHANGE_NULL_TO_READY:
			gst_rs_fec_dec_alloc_encoding_symbol_table(rs_fec_dec);
			/* For an explanation of why this is expected, see
			 * gst_rs_fec_dec_create_openfec_session(). */
			g_assert(rs_fec_dec->encoding_symbol_length == 0);
			break;

		case GST_STATE_CHANGE_READY_TO_PAUSED:
			/* Make sure states are at their initial value */
			gst_rs_fec_dec_reset_states(rs_fec_dec);
			break;
		default:
			break;
	}

	if ((result = GST_ELEMENT_CLASS(gst_rs_fec_dec_parent_class)->change_state(element, transition)) == GST_STATE_CHANGE_FAILURE)
		return result;

	switch (transition)
	{
		case GST_STATE_CHANGE_PAUSED_TO_READY:
			/* Make sure any incomplete source blocks are flushed
			 * and states are reset properly */
			gst_rs_fec_dec_flush(rs_fec_dec);
			/* Stream is done after switching to READY */
			rs_fec_dec->stream_started = FALSE;
			break;

		case GST_STATE_CHANGE_READY_TO_NULL:
			gst_rs_fec_dec_free_encoding_symbol_table(rs_fec_dec);

			/* Encoding symbol table and symbol memory blocks were freed.
			 * Set encoding_symbol_length to zero to ensure later runs
			 * don't try to free symbol memory blocks. See
			 * gst_rs_fec_dec_create_openfec_session() for more. */
			rs_fec_dec->encoding_symbol_length = 0;
			break;
		default:
			break;
	}

	return result;
}


static gboolean gst_rs_fec_dec_fecsource_event(GstPad *pad, GstObject *parent, GstEvent *event)
{
	GstRSFECDec *rs_fec_dec = GST_RS_FEC_DEC(parent);

	switch (GST_EVENT_TYPE(event))
	{
		case GST_EVENT_STREAM_START:
			/* Throw away incoming STREAM_START events
			 * this decoder generates its own STREAM_START events */
			gst_event_unref(event);
			return TRUE;

		case GST_EVENT_CAPS:
			/* Throw away incoming caps
			 * this decoder generates its own CAPS events */
			gst_event_unref(event);
			return TRUE;

		case GST_EVENT_SEGMENT:
			/* Throw away incoming segments
			 * this decoder generates its own SEGMENT events */
			gst_event_unref(event);
			return TRUE;

		case GST_EVENT_FLUSH_STOP:
			/* Lock to avoid race conditions between flushes here
			 * and chain function calls at the other sinkpad */
			RS_LOCK_MUTEX(rs_fec_dec);
			/* Make sure any incomplete source blocks are flushed
			 * and states are reset properly */
			gst_rs_fec_dec_flush(rs_fec_dec);
			RS_UNLOCK_MUTEX(rs_fec_dec);
			break;

		case GST_EVENT_EOS:
			/* Lock to avoid race conditions between here
			 * and chain function calls at the other sinkpad */
			RS_LOCK_MUTEX(rs_fec_dec);

			rs_fec_dec->fecsource_eos = TRUE;
			gst_rs_fec_dec_push_eos(rs_fec_dec);

			RS_UNLOCK_MUTEX(rs_fec_dec);
			break;

		default:
			break;
	}

	return gst_pad_event_default(pad, parent, event);
}


static gboolean gst_rs_fec_dec_fecrepair_event(GstPad *pad, GstObject *parent, GstEvent *event)
{
	GstRSFECDec *rs_fec_dec = GST_RS_FEC_DEC(parent);

	switch (GST_EVENT_TYPE(event))
	{
		case GST_EVENT_STREAM_START:
			/* Throw away incoming STREAM_START events
			 * this decoder generates its own STREAM_START events */
			gst_event_unref(event);
			return TRUE;

		case GST_EVENT_CAPS:
			/* Throw away incoming caps
			 * this decoder generates its own CAPS events */
			gst_event_unref(event);
			return TRUE;

		case GST_EVENT_SEGMENT:
			/* Throw away incoming segments
			 * this decoder generates its own SEGMENT events */
			gst_event_unref(event);
			return TRUE;

		case GST_EVENT_FLUSH_STOP:
			/* Lock to avoid race conditions between flushes here
			 * and chain function calls at the other sinkpad */
			RS_LOCK_MUTEX(rs_fec_dec);
			/* Make sure any incomplete source blocks are flushed
			 * and states are reset properly */
			gst_rs_fec_dec_flush(rs_fec_dec);
			RS_UNLOCK_MUTEX(rs_fec_dec);
			break;

		case GST_EVENT_EOS:
			/* Lock to avoid race conditions between here
			 * and chain function calls at the other sinkpad */
			RS_LOCK_MUTEX(rs_fec_dec);

			rs_fec_dec->fecrepair_eos = TRUE;
			gst_rs_fec_dec_push_eos(rs_fec_dec);

			RS_UNLOCK_MUTEX(rs_fec_dec);
			break;

		default:
			break;
	}

	return gst_pad_event_default(pad, parent, event);
}


static GstFlowReturn gst_rs_fec_dec_fecsource_chain(G_GNUC_UNUSED GstPad *pad, GstObject *parent, GstBuffer *buffer)
{
	GstRSFECDec *rs_fec_dec = GST_RS_FEC_DEC_CAST(parent);
	GstFlowReturn ret = GST_FLOW_OK;

	/* Lock to prevent race conditions between flushes, this chain function,
	 * and a chain function call at the other sinkpad */
	RS_LOCK_MUTEX(rs_fec_dec);

	if (rs_fec_dec->fecsource_eos)
	{
		GST_DEBUG_OBJECT(rs_fec_dec, "received FEC source data after EOS was received - dropping buffer");
		gst_buffer_unref(buffer);
		ret = GST_FLOW_EOS;
	}
	else
		ret = gst_rs_fec_dec_insert_fec_packet(rs_fec_dec, buffer, TRUE);

	RS_UNLOCK_MUTEX(rs_fec_dec);

	return ret;
}


static GstFlowReturn gst_rs_fec_dec_fecrepair_chain(G_GNUC_UNUSED GstPad *pad, GstObject *parent, GstBuffer *buffer)
{
	GstRSFECDec *rs_fec_dec = GST_RS_FEC_DEC_CAST(parent);
	GstFlowReturn ret = GST_FLOW_OK;

	/* Lock to prevent race conditions between flushes, this chain function,
	 * and a chain function call at the other sinkpad */
	RS_LOCK_MUTEX(rs_fec_dec);

	if (rs_fec_dec->fecrepair_eos)
	{
		GST_DEBUG_OBJECT(rs_fec_dec, "received FEC repair data after EOS was received - dropping buffer");
		gst_buffer_unref(buffer);
		ret = GST_FLOW_EOS;
	}
	else
		ret = gst_rs_fec_dec_insert_fec_packet(rs_fec_dec, buffer, FALSE);

	RS_UNLOCK_MUTEX(rs_fec_dec);

	return ret;
}


static void gst_rs_fec_dec_alloc_encoding_symbol_table(GstRSFECDec *rs_fec_dec)
{
	g_assert(rs_fec_dec->allocated_encoding_symbol_table == NULL);

	GST_DEBUG_OBJECT(rs_fec_dec, "allocating symbol and output ADU tables  (num encoding symbols: %u  num source symbols: %u)", rs_fec_dec->num_encoding_symbols, rs_fec_dec->num_source_symbols);

	/* Create encoding symbol tables for OpenFEC. In the tables, the
	 * source symbols must come in first, in the same order as they
	 * are in the queue. Directly behind the source symbols, the
	 * repair symbols are located. The memory blocks of the
	 * individual symbols are allocated an inserted into the
	 * allocated_encoding_symbol_table later on-demand.*/
	rs_fec_dec->allocated_encoding_symbol_table = g_slice_alloc0(sizeof(void *) * rs_fec_dec->num_encoding_symbols);
	rs_fec_dec->received_encoding_symbol_table = g_slice_alloc0(sizeof(void *) * rs_fec_dec->num_encoding_symbols);
	rs_fec_dec->recovered_encoding_symbol_table = g_slice_alloc0(sizeof(void *) * rs_fec_dec->num_encoding_symbols);

	rs_fec_dec->fec_repair_packet_mapinfos = g_slice_alloc0(sizeof(GstMapInfo) * rs_fec_dec->num_repair_symbols);
}


static void gst_rs_fec_dec_free_encoding_symbol_table(GstRSFECDec *rs_fec_dec)
{
	g_assert(rs_fec_dec->allocated_encoding_symbol_table != NULL);

	GST_DEBUG_OBJECT(rs_fec_dec, "freeing symbol and output ADU tables  (num encoding symbols: %u  num source symbols: %u)", rs_fec_dec->num_encoding_symbols, rs_fec_dec->num_source_symbols);

	/* Deallocate symbol memory blocks first */
	if (rs_fec_dec->encoding_symbol_length != 0)
	{
		guint i;
		/* See gst_rs_fec_dec_create_openfec_session() for an explanation
		 * why only the source symbols - and not all symbols - are freed */
		for (i = 0; i < rs_fec_dec->num_source_symbols; ++i)
			g_slice_free1(rs_fec_dec->encoding_symbol_length, rs_fec_dec->allocated_encoding_symbol_table[i]);
	}

	/* Deallocate the tables */
	g_slice_free1(sizeof(void *) * rs_fec_dec->num_encoding_symbols, rs_fec_dec->allocated_encoding_symbol_table);
	g_slice_free1(sizeof(void *) * rs_fec_dec->num_encoding_symbols, rs_fec_dec->received_encoding_symbol_table);
	g_slice_free1(sizeof(void *) * rs_fec_dec->num_encoding_symbols, rs_fec_dec->recovered_encoding_symbol_table);

	g_slice_free1(sizeof(GstMapInfo) * rs_fec_dec->num_repair_symbols, rs_fec_dec->fec_repair_packet_mapinfos);

	rs_fec_dec->allocated_encoding_symbol_table = NULL;
	rs_fec_dec->received_encoding_symbol_table = NULL;
	rs_fec_dec->recovered_encoding_symbol_table = NULL;
}


static void gst_rs_fec_dec_source_packet_read_payload_id(GstBuffer *fec_source_packet, guint *source_block_nr, guint *esi)
{
	GstMapInfo map_info;
	gst_buffer_map(fec_source_packet, &map_info, GST_MAP_READ);

	/* In the FEC payload ID, the source block nr comes first, then the ESI,
	 * then the source block length (not used here) */

	if (source_block_nr != NULL)
	{
		guint8 *bytes = &(map_info.data[map_info.size - 6]);
		*source_block_nr = (((guint)(bytes[0])) << 16) | (((guint)(bytes[1])) << 8) | ((guint)(bytes[2]));
	}

	if (esi != NULL)
		*esi = map_info.data[map_info.size - 3];

	gst_buffer_unmap(fec_source_packet, &map_info);
}


static void gst_rs_fec_dec_repair_packet_read_payload_id(GstBuffer *fec_repair_packet, guint *source_block_nr, guint *esi)
{
	GstMapInfo map_info;
	gst_buffer_map(fec_repair_packet, &map_info, GST_MAP_READ);

	/* In the FEC payload ID, the source block nr comes first, then the ESI,
	 * then the source block length (not used here) */

	if (source_block_nr != NULL)
	{
		/* Source block nr is stored as a 24-bit big endian unsigned integer */
		guint8 *bytes = &(map_info.data[0]);
		*source_block_nr = (((guint)(bytes[0])) << 16) | (((guint)(bytes[1])) << 8) | ((guint)(bytes[2]));
	}

	if (esi != NULL)
		*esi = map_info.data[3];

	gst_buffer_unmap(fec_repair_packet, &map_info);
}


static GstFlowReturn gst_rs_fec_dec_insert_fec_packet(GstRSFECDec *rs_fec_dec, GstBuffer *fec_packet, gboolean is_source_packet)
{
	guint source_block_nr, esi;
	GstRSFECDecSourceBlock *source_block;
	GstBuffer *adu;
	gsize adu_length;
	gchar const *packet_str = is_source_packet ? "source" : "repair";
	GstFlowReturn ret = GST_FLOW_OK;

	/* fec_packet is not ref'd here, but it is unref'd when the source block is destroyed */

	/* Get the source block nr and ESI of the packet */
	if (is_source_packet)
		gst_rs_fec_dec_source_packet_read_payload_id(fec_packet, &source_block_nr, &esi);
	else
		gst_rs_fec_dec_repair_packet_read_payload_id(fec_packet, &source_block_nr, &esi);
	GST_LOG_OBJECT(rs_fec_dec, "adding FEC %s packet with source block nr #%u and ESI %u", packet_str, source_block_nr, esi);

	/* Get the corresponding source block; create a new one if it does not exist */
	source_block = gst_rs_fec_dec_fetch_source_block(rs_fec_dec, source_block_nr);
	if (source_block == NULL)
	{
		GST_LOG_OBJECT(rs_fec_dec, "source block with nr #%u not present - creating", source_block_nr);
		source_block = gst_rs_fec_dec_create_source_block(rs_fec_dec, source_block_nr);
	}

	/* Discard packet if it is too old (for a definiton of what "too old" means, see
	 * the description of the max_source_block_age value in the header) */
	if (!gst_rs_fec_dec_is_source_block_nr_recent_enough(source_block_nr, rs_fec_dec->most_recent_block_nr, rs_fec_dec->max_source_block_age))
	{
		GST_LOG_OBJECT(rs_fec_dec, "FEC %s packet's block nr is too old (packet block nr: %u most recent nr: %u) - discarding obsolete packet", packet_str, source_block_nr, rs_fec_dec->most_recent_block_nr);
		gst_buffer_unref(fec_packet);
		return GST_FLOW_OK;
	}

	/* If this source block is already completed, discard unnecessary extra data and exit
	 * This can for example happen if the incoming packets are duplicated by the
	 * transport layer, or because there were enough source and/or repair symbols earlier
	 * to process and complete this source block */
	if (source_block->is_complete)
	{
		GST_LOG_OBJECT(rs_fec_dec, "source block #%u is already completed - discarding unnecessary FEC %s packet with ESI %u", source_block_nr, packet_str, esi);
		gst_buffer_unref(fec_packet);
		return GST_FLOW_OK;
	}

	/* Find out if this packet has already been received, and if so, discard and exit */
	if (SOURCE_BLOCK_IS_FLAG_SET(source_block, esi))
	{
		GST_LOG_OBJECT(rs_fec_dec, "FEC %s packet with ESI %u already in source block #%u - discarding duplicate packet", packet_str, esi, source_block_nr);
		gst_buffer_unref(fec_packet);
		return GST_FLOW_OK;
	}

	/* Packet has not been received yet; mark it as received now */
	SOURCE_BLOCK_SET_FLAG(source_block, esi);

	if (is_source_packet)
	{
		/* Add the packet to the list, and increase the counter */
		source_block->source_packets = g_slist_prepend(source_block->source_packets, fec_packet);
		source_block->num_source_packets++;
		GST_LOG_OBJECT(rs_fec_dec, "added FEC source packet to source block #%u ; there are %u source packets in the block now", source_block_nr, source_block->num_source_packets);

		/* Extract ADU from the packet, and insert it in the output_adu_table */
		adu_length = gst_buffer_get_size(fec_packet) - 6;
		/* Using a GStreamer subbuffer to avoid unnecessary copies */
		adu = gst_buffer_copy_region(fec_packet, GST_BUFFER_COPY_MEMORY | GST_BUFFER_COPY_MERGE, 0, adu_length);
		source_block->output_adu_table[esi] = adu;

		/* If no sorting is needed, then we can output the ADU right away.
		 * Apply timestamping if necessary, and then pushed. When the
		 * block is processed, these ADUs will not be pushed again. */
		if (!rs_fec_dec->sort_output)
		{
			gst_buffer_ref(adu);

			GST_LOG_OBJECT(rs_fec_dec, "pushing ADU with ESI %u from source block %u", esi, source_block_nr);

			if ((ret = gst_rs_fec_dec_push_adu(rs_fec_dec, adu)) != GST_FLOW_OK)
				return ret;
		}
	}
	else
	{
		/* Add the packet to the list, and increase the counter */
		source_block->repair_packets = g_slist_prepend(source_block->repair_packets, fec_packet);
		source_block->num_repair_packets++;
		GST_LOG_OBJECT(rs_fec_dec, "added FEC repair packet to source block #%u ; there are %u repair packets in the block now", source_block_nr, source_block->num_repair_packets);
	}

	if (gst_rs_fec_dec_can_source_block_be_processed(rs_fec_dec, source_block))
	{
		GST_LOG_OBJECT(rs_fec_dec, "source block #%u can be processed now", source_block->block_nr);
		ret = gst_rs_fec_dec_process_source_block(rs_fec_dec, source_block);

		/* If sorting is disabled, we can push any ADUs from the source block
		 * immediately. Do so, and remove the pushed source block from the table. */
		if (!rs_fec_dec->sort_output)
		{
			gst_rs_fec_dec_destroy_source_block(rs_fec_dec, source_block);
			g_hash_table_remove(rs_fec_dec->source_block_table, GINT_TO_POINTER(source_block_nr));
		}
	}

	if (ret == GST_FLOW_OK)
		return gst_rs_fec_dec_prune_source_block_table(rs_fec_dec, source_block_nr);
	else
		return ret;
}


static GstRSFECDecSourceBlock* gst_rs_fec_dec_fetch_source_block(GstRSFECDec *rs_fec_dec, guint block_nr)
{
	return (GstRSFECDecSourceBlock *)g_hash_table_lookup(rs_fec_dec->source_block_table, GINT_TO_POINTER(block_nr));
}


static GstRSFECDecSourceBlock* gst_rs_fec_dec_create_source_block(GstRSFECDec *rs_fec_dec, guint block_nr)
{
	/* Create a new source block, and insert it into the source block table */
	GstRSFECDecSourceBlock *source_block = g_slice_alloc0(sizeof(GstRSFECDecSourceBlock));
	g_hash_table_insert(rs_fec_dec->source_block_table, GINT_TO_POINTER(block_nr), source_block);

	/* Initialize the source block */
	source_block->block_nr = block_nr;
	source_block->output_adu_table = g_slice_alloc0(sizeof(void *) * rs_fec_dec->num_source_symbols);

	GST_LOG_OBJECT(rs_fec_dec, "created source block #%u", block_nr);

	return source_block;
}


static void gst_rs_fec_dec_destroy_source_block(GstRSFECDec *rs_fec_dec, GstRSFECDecSourceBlock *source_block)
{
	GSList *node;
	guint block_nr = source_block->block_nr;
	guint i;

	/* Clean up all queued FEC source packets */
	if (source_block->source_packets != NULL)
	{
		GST_LOG_OBJECT(rs_fec_dec, "cleaning up queued FEC source packets in source block #%u", block_nr);

		for (node = source_block->source_packets; node != NULL; node = node->next)
		{
			GstBuffer *buffer = (GstBuffer *)(node->data);
			gst_buffer_unref(buffer);
		}

		g_slist_free(source_block->source_packets);
	}

	/* Clean up all queued FEC repair packets */
	if (source_block->repair_packets != NULL)
	{
		GST_LOG_OBJECT(rs_fec_dec, "cleaning up queued FEC repair packets in source block #%u", block_nr);

		for (node = source_block->repair_packets; node != NULL; node = node->next)
		{
			GstBuffer *buffer = (GstBuffer *)(node->data);
			gst_buffer_unref(buffer);
		}

		g_slist_free(source_block->repair_packets);
	}

	/* Cleanup the output_adu_table */
	for (i = 0; i < rs_fec_dec->num_source_symbols; ++i)
	{
		GstBuffer *adu = source_block->output_adu_table[i];
		if (adu != NULL)
			gst_buffer_unref(adu);
	}
	g_slice_free1(sizeof(void *) * rs_fec_dec->num_source_symbols, source_block->output_adu_table);

	/* Source block is cleaned up, now free it */
	g_slice_free1(sizeof(GstRSFECDecSourceBlock), source_block);

	GST_LOG_OBJECT(rs_fec_dec, "destroyed source block #%u", block_nr);
}


static gboolean gst_rs_fec_dec_can_source_block_be_processed(GstRSFECDec *rs_fec_dec, GstRSFECDecSourceBlock *source_block)
{
	/* Recovery via Reed-Solomon erasure coding can commence once at least
	 * num_source_symbols packets have been received */
	return (source_block->num_source_packets + source_block->num_repair_packets) >= rs_fec_dec->num_source_symbols;
}


static GstFlowReturn gst_rs_fec_dec_process_source_block(GstRSFECDec *rs_fec_dec, GstRSFECDecSourceBlock *source_block)
{
	of_status_t status;
	of_session_t *session = NULL;
	GSList *node;
	guint esi;
	guint node_count;
	gsize encoding_symbol_length;
	guint adu_flow_id = 0; /* XXX: XXX: Currently, only one flow (flow 0) is supported */
	GstFlowReturn ret = GST_FLOW_OK;
	gboolean repair_packets_mapped = FALSE;

	if (source_block->num_repair_packets == 0)
	{
		/* Special case: all source and no repair packets of this source block received,
		 * or num_repair_symbols is 0. Recovering symbols is unnecessary (and actually
		 * not even doable). So, just mark the source block as complete, and done. */

		/* If this place is reached even though not all source packets have been
		 * received, then something went wrong when inserting packes. */
		g_assert(source_block->num_source_packets == rs_fec_dec->num_source_symbols);

		/* All ADUs present, mark it as done. (ADUs were extracted earlier in the
		 * gst_rs_fec_dec_insert_fec_packet() function.) */
		source_block->is_complete = TRUE;
	}
	else
	{
		/* This point is reached in the more general case that not all FEC source packets
		 * were received */

		/* The encoding_symbol_length needs to be determined. Use the length of the
		 * first repair packet to this end. All repair packets are of the same length,
		 * which is encoding_symbol_length + 6 (the FEC payload ID has 6 bytes). */
		encoding_symbol_length = gst_buffer_get_size((GstBuffer *)(source_block->repair_packets->data)) - 6;

		/* Set up OpenFEC. Unlike encoders, OpenFEC decoder sessions can only be used once
		 * for each source block, which is why session are created and released here.
		 * The symbol memory blocks, however, are reallocated only if the encoding_symbol_length
		 * changed since the last call. */
		if ((session = gst_rs_fec_dec_create_openfec_session(rs_fec_dec, encoding_symbol_length)) == NULL)
		{
			GST_ERROR_OBJECT(rs_fec_dec, "could not create OpenFEC session");
			return GST_FLOW_ERROR;
		}

		/* Set all of the pointers in the received_encoding_symbol_table to NULL to
		 * be able to determine later which packets have been lost (needed by OpenFEC) */
		memset(rs_fec_dec->received_encoding_symbol_table, 0, sizeof(void*) * rs_fec_dec->num_encoding_symbols);

		/* Go over each FEC source packet, create a source symbol out of its ADU
		 * for the OpenFEC decoder, and store the ADU in the output_adu_table.
		 * Also update the received_encoding_symbol_table; for each source symbol,
		 * set the appropriate entry in this table to the corresponding entry in the
		 * allocated_encoding_symbol_table. In other words, all entries in the
		 * received_encoding_symbol_table which correspond to a received source symbol
		 * will be non-NULL after this loop, and the others will be NULL. */
		for (node = source_block->source_packets; node != NULL; node = node->next)
		{
			guint esi;
			GstBuffer *adu;
			gsize adu_length;
			gsize padding_length;
			guint8 *adui_memblock;
			GstBuffer *fec_source_packet = (GstBuffer *)(node->data);

			/* Get the ESI of the packet */
			gst_rs_fec_dec_source_packet_read_payload_id(fec_source_packet, NULL, &esi);

			/* Check for invalid source symbol ESIs
			 * Valid source symbol ESIs are in the range (0..k-1) */
			g_assert(esi < rs_fec_dec->num_source_symbols);

			/* ADU = FEC source packet minus the trailing 6 bytes which
			 * make up the FEC payload ID */
			adu_length = gst_buffer_get_size(fec_source_packet) - 6;

			/* All encoding symbols are of equal length, and a source symbol
			 * is an ADU with 3 extra bytes prepended and padding njullbytes
			 * appended to ensure that their length is encoding_symbol_length.
			 * This means that (adu_length+3) <= source_symbol_length = encoding_symbol_length. */
			g_assert((adu_length + 3) <= encoding_symbol_length);

			/* Fetch the ADU with the given ESI. The ADUs are already available,
			 * since they were previously extracted from the packet in the
			 * gst_rs_fec_dec_insert_fec_packet() function. */
			adu = source_block->output_adu_table[esi];

			/* Calculate the number of trailing padding bytes needed. */
			padding_length = encoding_symbol_length - (adu_length + 3);

			/* Assemble a source symbol (= an ADUI) by getting the pointer of the
			 * corresponding symbol memory block in the allocated_encoding_symbol_table
			 * (all of these blocks have*a length that equals encoding_symbol_length),
			 * and writing flow ID and ADU length data into it, followed by the ADU data
			 * itself. This recreates the ADUIs that were used inside the encoder. */
			adui_memblock = rs_fec_dec->allocated_encoding_symbol_table[esi];
			adui_memblock[0] = adu_flow_id;
			adui_memblock[1] = (adu_length & 0xFF00) >> 8;
			adui_memblock[2] = (adu_length & 0xFF);
			gst_buffer_extract(adu, 0, adui_memblock + 3, adu_length);

			/* Put the pointer to the ADUI in the received_encoding_symbol_table,
			 * using the ESI as the index. We received the ADU, it is not lost.
			 * By copying the pointer into this table, we inform OpenFEC that the
			 * source symbol (= ADUI) with the given ESI has been received. */
			rs_fec_dec->received_encoding_symbol_table[esi] = adui_memblock;

			GST_LOG_OBJECT(rs_fec_dec, "inserted source symbol into encoding symbol table:  ESI: %u  ADU flow ID: %u  ADU length: %" G_GSIZE_FORMAT "  padding: %" G_GSIZE_FORMAT, esi, adu_flow_id, adu_length, padding_length);

			/* Set padding nullbytes to the source symbol to 0 */
			if (padding_length > 0)
				memset(adui_memblock + adu_length + 3, 0, padding_length);

			/* If no sorting is needed, then this received ADU has already been
			 * pushed earlier, when it was inserted. This means that it is no
			 * longer needed anywhere, so unref the buffer, and mark its entry
			 * as NULL to ensure it is not unref'd again in
			 * gst_rs_fec_dec_push_source_block(). */
			if (!rs_fec_dec->sort_output)
			{
				gst_buffer_unref(adu);
				source_block->output_adu_table[esi] = NULL;
			}
		}

		/* Go over each FEC repair packet, map it, and put a pointer to the
		 * repair symbol data inside the packet in the received_encoding_symbol_table. */
		node_count = 0;
		for (node = source_block->repair_packets; node != NULL; node = node->next)
		{
			guint esi;
			GstMapInfo *map_info;
			GstBuffer *fec_repair_packet = (GstBuffer *)(node->data);

			g_assert(node_count < rs_fec_dec->num_repair_symbols);

			gst_rs_fec_dec_repair_packet_read_payload_id(fec_repair_packet, NULL, &esi);

			g_assert((esi >= rs_fec_dec->num_source_symbols) && (esi < rs_fec_dec->num_encoding_symbols));

			/* Map the FEC repair packet, and keep the mapping information in the
			 * fec_repair_packet_mapinfos array. This way, after recovery is
			 * finished, all of the buffers can be unmapped.
			 * After this loop finishes, the first N entries in the array are
			 * filled with valid mapinfo, where N equals the number of nodes in
			 * the repair_packets list. */
			map_info = &(rs_fec_dec->fec_repair_packet_mapinfos[node_count]);
			gst_buffer_map(fec_repair_packet, map_info, GST_MAP_READ);

			/* The first 6 bytes in the FEC repair packet are its payload ID.
			 * The following bytes are the repair symbol data, which is what
			 * OpenFEC needs. */
			rs_fec_dec->received_encoding_symbol_table[esi] = map_info->data + 6;

			/* Incrementing this counter is necessary for storing the
			 * map information */
			node_count++;
		}
		repair_packets_mapped = TRUE;

		/* Inform OpenFEC about the received symbols. At this point, any encoding symbols that
		 * have been received will have a non-NULL entry in the received_encoding_symbol_table.
		 * Those who have not been received are considered lost at this point and have NULL
		 * entries in the table. */
		if ((status = of_set_available_symbols(session, rs_fec_dec->received_encoding_symbol_table)) != OF_STATUS_OK)
		{
			GST_ERROR_OBJECT(rs_fec_dec, "could not set available symbols: %s", gst_rs_fec_dec_get_status_name(status));
			CHECK_IF_FATAL_ERROR(rs_fec_dec, status);
			ret = GST_FLOW_ERROR;
			goto cleanup;
		}

		/* Instruct OpenFEC to perform the actual decoding/recovery. The source symbols in the
		 * received_encoding_symbol_table with NULL entries will be recovered here, using the
		 * information from the received source and repair symbols. Lost repair symbols are
		 * not recovered, since they are of no interest.
		 * Internally, of_finish_decoding() will call gst_rs_fec_dec_openfec_source_symbol_cb()
		 * to retrieve a pointer for memory blocks where it can store recovered source symbols.
		 * Typically, this callback is used for custom allocators, but here, it simply returns
		 * a pointer from the allocated_encoding_symbol_table, using the ESI as index. This
		 * avoids unnecessary reallocations during decoding. */
		if ((status = of_finish_decoding(session)) != OF_STATUS_OK)
		{
			GST_ERROR_OBJECT(rs_fec_dec, "could not finish decoding: %s", gst_rs_fec_dec_get_status_name(status));
			CHECK_IF_FATAL_ERROR(rs_fec_dec, status);
			ret = GST_FLOW_ERROR;
			goto cleanup;
		}

		/* Fill the recovered_encoding_symbol_table with pointers for recovered source symbols.
		 * For each entry in the received_encoding_symbol_table which is NULL, the corresponding
		 * entry in recovered_encoding_symbol_table will be non-NULL. */
		if ((status = of_get_source_symbols_tab(session, rs_fec_dec->recovered_encoding_symbol_table)) != OF_STATUS_OK)
		{
			GST_ERROR_OBJECT(rs_fec_dec, "could not get the recovered symbols: %s", gst_rs_fec_dec_get_status_name(status));
			CHECK_IF_FATAL_ERROR(rs_fec_dec, status);
			ret = GST_FLOW_ERROR;
			goto cleanup;
		}

		/* Output all received and recovered ADUs, in order of their ESI. */
		for (esi = 0; esi < rs_fec_dec->num_source_symbols; ++esi)
		{
			if (rs_fec_dec->received_encoding_symbol_table[esi] == NULL)
			{
				/* ADU with with the given ESI was recovered, not received.
				 * Extract this ADU from the recovered source symbol and
				 * put the recovered ADU into the source block's output_adu_table. */

				GstBuffer *adu;
				guint adu_flow, adu_length;
				guint8 *recovered_sym_memblock = rs_fec_dec->recovered_encoding_symbol_table[esi];

				g_assert(recovered_sym_memblock != NULL);

				/* Extract flow ID */
				adu_flow = recovered_sym_memblock[0];
				/* Extract ADU length (16-bit big endian unsigned integer) */
				adu_length = (((guint)(recovered_sym_memblock[1])) << 8) | ((guint)(recovered_sym_memblock[2]));

				if (adu_flow != 0)
				{
					GST_ELEMENT_WARNING(rs_fec_dec, STREAM, DECODE, ("multiple ADU flows are currently not supported"), ("recovered ADU has flow ID %u", adu_flow));
					continue;
				}

				GST_LOG_OBJECT(rs_fec_dec, "pushing recovered ADU with ESI %u  (source block: #%u  length: %u)", esi, source_block->block_nr, adu_length);

				/* Create a new GstBuffer and copy the ADU bytes into it.
				 * The ADU bytes are located right after the 3 initial bytes
				 * (the ADU flow and ADU length). The ADU bytes need to be
				 * copied, since the symbol memory block referred to by
				 * the recovered_sym_memblock pointer is reused later for
				 * subsequent decoding, so we cannot simply wrap that pointer
				 * in a GstMemory instance. Otherwise, race conditions could
				 * occur if downstream then tries to access this data at the
				 * same time. */
				adu = gst_buffer_new_allocate(NULL, adu_length, NULL);
				gst_buffer_fill(adu, 0, recovered_sym_memblock + 3, adu_length);

				if (rs_fec_dec->sort_output)
				{
					/* Put the recovered ADU into the output_adu_table */
					source_block->output_adu_table[esi] = adu;
				}
				else
				{
					/* Sorting is disabled, so we can push the ADU
					 * immediately. */
					source_block->output_adu_table[esi] = NULL;
					if ((ret = gst_rs_fec_dec_push_adu(rs_fec_dec, adu)) != GST_FLOW_OK)
					{
						GST_DEBUG_OBJECT(rs_fec_dec, "got return value %s while pushing recovered ADU", gst_flow_get_name(ret));
						goto cleanup;
					}
				}
			}
		}
	}

	source_block->is_complete = TRUE;

cleanup:
	if (repair_packets_mapped)
	{
		/* Here, unmap any previously mapped FEC repair packets. */

		node_count = 0;
		for (node = source_block->repair_packets; node != NULL; node = node->next)
		{
			GstMapInfo *map_info;
			GstBuffer *fec_repair_packet = (GstBuffer *)(node->data);

			g_assert(node_count < rs_fec_dec->num_repair_symbols);

			map_info = &(rs_fec_dec->fec_repair_packet_mapinfos[node_count]);
			gst_buffer_unmap(fec_repair_packet, map_info);

			node_count++;
		}
	}

	/* Release the OpenFEC session */
	if ((session != NULL) && ((status = of_release_codec_instance(session)) != OF_STATUS_OK))
	{
		GST_ERROR_OBJECT(rs_fec_dec, "could not release codec instance: %s", gst_rs_fec_dec_get_status_name(status));
		CHECK_IF_FATAL_ERROR(rs_fec_dec, status);
		ret = FALSE;
	}

	return ret;
}


static GstFlowReturn gst_rs_fec_dec_push_source_block(GstRSFECDec *rs_fec_dec, GstRSFECDecSourceBlock *source_block)
{
	guint esi;
	GstFlowReturn ret = GST_FLOW_OK;
	gboolean push_adus = TRUE;

	/* Send stream-start and segment events if necessary */
	gst_rs_fec_dec_push_stream_start(rs_fec_dec);
	gst_rs_fec_dec_push_segment(rs_fec_dec);

	for (esi = 0; esi < rs_fec_dec->num_source_symbols; ++esi)
	{
		GstBuffer *adu = source_block->output_adu_table[esi];
		source_block->output_adu_table[esi] = NULL;

		if (adu == NULL)
			continue;

		if (push_adus)
		{
			GST_LOG_OBJECT(rs_fec_dec, "pushing ADU with ESI %u from source block %u", esi, source_block->block_nr);
			if ((ret = gst_rs_fec_dec_push_adu(rs_fec_dec, adu)) != GST_FLOW_OK)
			{
				GST_DEBUG_OBJECT(rs_fec_dec, "got return value %s while pushing ADUs from source block #%u; discarding the remaining ADUs", gst_flow_get_name(ret), source_block->block_nr);
				push_adus = FALSE;
			}
		}
		else
			gst_buffer_unref(adu);
	}

	return ret;
}


static gboolean gst_rs_fec_dec_is_source_block_nr_newer(guint candidate_block_nr, guint reference_block_nr)
{
	/* A source block number is considered "newer" if it is in the range
	 * (reference_block_nr+1 ... (reference_block_nr+(2^24-1)) mod (2^24)).
	 * 2^22 is chosen, since it is unlikely that a number comes along which
	 * is newer by a value of over 4.2 million. This defined range is
	 * necessary, since due to the wrap-around nature of source block numbers,
	 * it is otherwise not possible to distinguish between older and newer
	 * numbers. For example, if the maximum age is 2, and the current block is
	 * 0, then the numbers 0 and 16777215 are "older, but still OK", and
	 * anything below 16777215 is "too old". Anything above 0 is "newer".
	 * But this contradicts itself, since foe example 16777214 > 0. By
	 * introducing a range for newer values, it is resolved. In this example,
	 * newer values range from 1 to 2^22, and the remaining values are
	 * considered current, old, or too old. */

	guint const newer_range = (1u << 22);
	guint const total_range = (1u << 24);

	guint start = reference_block_nr + 1;
	guint end = (reference_block_nr + (newer_range - 1)) & (total_range - 1);

	return gst_rs_fec_dec_check_if_source_block_in_range(candidate_block_nr, start, end);
}


static gboolean gst_rs_fec_dec_is_source_block_nr_recent_enough(guint candidate_block_nr, guint reference_block_nr, guint max_age)
{
	/* See the explanation in gst_rs_fec_dec_is_source_block_nr_newer() for
	 * details.
	 *
	 * The "recent enough" range also includes the "newer range", since otherwise
	 * this function would incorrectly classify newer values as "too old". */

	guint const newer_range = (1u << 22);
	guint const total_range = (1u << 24);

	guint start = (reference_block_nr + total_range - (max_age - 1)) & (total_range - 1);
	guint end = (reference_block_nr + (newer_range - 1)) & (total_range - 1);

	return gst_rs_fec_dec_check_if_source_block_in_range(candidate_block_nr, start, end);
}


static gboolean gst_rs_fec_dec_check_if_source_block_in_range(guint block_nr, guint start, guint end)
{
	if (start < end)
		return (block_nr >= start) && (block_nr <= end);
	else if (start > end)
		return (block_nr <= end) || (block_nr >= start);
	else
		return block_nr == start;
}


static gint gst_rs_fec_dec_compare_source_blocks(gconstpointer first, gconstpointer second)
{
	/* This function is used during source block table pruning, when pruned source
	 * blocks get sorted prior to being pushed downstream. */

	GstRSFECDecSourceBlock *first_source_block = (GstRSFECDecSourceBlock *)first;
	GstRSFECDecSourceBlock *second_source_block = (GstRSFECDecSourceBlock *)second;
	guint first_block_nr = first_source_block->block_nr;
	guint second_block_nr = second_source_block->block_nr;

	return (first_block_nr < second_block_nr) ? -1 : ((first_block_nr > second_block_nr) ? 1 : 0);
}


static GstFlowReturn gst_rs_fec_dec_prune_source_block_table(GstRSFECDec *rs_fec_dec, guint source_block_nr)
{
	GstFlowReturn ret = GST_FLOW_OK;

	if (rs_fec_dec->first_pruning)
	{
		rs_fec_dec->most_recent_block_nr = source_block_nr;
		rs_fec_dec->first_pruning = FALSE;
	}
	else if (source_block_nr != rs_fec_dec->most_recent_block_nr)
	{
		/* If the source_block_nr is newer than most_recent_block_nr,
		 * then we have to check all source blocks in the table. If
		 * they are too old, they need to be pruned. They are removed
		 * from the hash table, sorted in order or their block numbers,
		 * and pushed downstream.
		 * If the source_block_nr is older, nothing is done, because
		 * at this point, a source block nr is either slightly old
		 * (but still recent enough), or the same as most_recent_block_nr,
		 * or newer. */
		if (gst_rs_fec_dec_is_source_block_nr_newer(source_block_nr, rs_fec_dec->most_recent_block_nr))
		{
			gpointer value;
			GHashTableIter iter;
			GSList *node, *pruned_block_list = NULL;

			/* Update the most_recent_block_nr */
			rs_fec_dec->most_recent_block_nr = source_block_nr;

			/* Iterate over all entries */
			g_hash_table_iter_init(&iter, rs_fec_dec->source_block_table);
			while (g_hash_table_iter_next(&iter, NULL, &value))
			{
				GstRSFECDecSourceBlock *source_block = (GstRSFECDecSourceBlock *)value;
				if (!gst_rs_fec_dec_is_source_block_nr_recent_enough(source_block->block_nr, rs_fec_dec->most_recent_block_nr, rs_fec_dec->max_source_block_age))
				{
					/* This source block is too old and needs to be pruned.
					 * Insert it in the block list if sorting is enabled,
					 * or just destroy it right away otherwise. */

					if (rs_fec_dec->sort_output)
					{
						GST_LOG_OBJECT(rs_fec_dec, "inserting source block #%u into the pruning list", source_block->block_nr);
						pruned_block_list = g_slist_prepend(pruned_block_list, source_block);
					}
					else
					{
						GST_LOG_OBJECT(rs_fec_dec, "discarding source block #%u", source_block->block_nr);
						gst_rs_fec_dec_destroy_source_block(rs_fec_dec, source_block);
					}

					g_hash_table_iter_remove(&iter);
				}
			}

			/* Sort pruned_block_list by the block numbers to ensure they
			 * are pushed in order. */
			if (pruned_block_list != NULL)
				pruned_block_list = g_slist_sort(pruned_block_list, gst_rs_fec_dec_compare_source_blocks);

			/* Push all pruned source blocks downstream. At this point, it
			 * is guaranteed that both they and their ADUs are in order. */
			for (node = pruned_block_list; node != NULL; node = node->next)
			{
				GstRSFECDecSourceBlock *source_block = (GstRSFECDecSourceBlock *)(node->data);

				/* This place should not be reachable if sorting is disabled */
				g_assert(rs_fec_dec->sort_output);

				if (ret == GST_FLOW_OK)
				{
					gchar const *complete_str = source_block->is_complete ? "complete" : "incomplete";

					if ((ret = gst_rs_fec_dec_push_source_block(rs_fec_dec, source_block)) != GST_FLOW_OK)
						GST_DEBUG_OBJECT(rs_fec_dec, "got return value %s while pushing pruned %s source block #%u downstream; discarding the remaining pruned source blocks", gst_flow_get_name(ret), complete_str, source_block->block_nr);
					else
						GST_LOG_OBJECT(rs_fec_dec, "pushed pruned %s source block #%u downstream", complete_str, source_block->block_nr);
				}

				gst_rs_fec_dec_destroy_source_block(rs_fec_dec, source_block);
			}

			/* All done. Destroy block list. */
			g_slist_free(pruned_block_list);
		}
	}

	return ret;
}


static GstFlowReturn gst_rs_fec_dec_drain_source_block_table(GstRSFECDec *rs_fec_dec)
{
	GstFlowReturn ret = GST_FLOW_OK;
	gpointer value;
	GHashTableIter iter;
	GSList *node, *drain_block_list = NULL;

	/* Iterate over all entries */
	g_hash_table_iter_init(&iter, rs_fec_dec->source_block_table);
	while (g_hash_table_iter_next(&iter, NULL, &value))
	{
		GstRSFECDecSourceBlock *source_block = (GstRSFECDecSourceBlock *)value;

		GST_LOG_OBJECT(rs_fec_dec, "inserting source block #%u into the draining list", source_block->block_nr);
		drain_block_list = g_slist_prepend(drain_block_list, source_block);
		g_hash_table_iter_remove(&iter);
	}

	/* Sort drain_block_list by the block numbers to ensure they
	 * are pushed in order. */
	if (drain_block_list != NULL)
		drain_block_list = g_slist_sort(drain_block_list, gst_rs_fec_dec_compare_source_blocks);

	/* Push all source blocks downstream. At this point, it
	 * is guaranteed that both they and their ADUs are in order. */
	for (node = drain_block_list; node != NULL; node = node->next)
	{
		GstRSFECDecSourceBlock *source_block = (GstRSFECDecSourceBlock *)(node->data);

		if (ret == GST_FLOW_OK)
		{
			gchar const *complete_str = source_block->is_complete ? "complete" : "incomplete";

			if ((ret = gst_rs_fec_dec_push_source_block(rs_fec_dec, source_block)) != GST_FLOW_OK)
				GST_DEBUG_OBJECT(rs_fec_dec, "got return value %s while pushing %s source block #%u downstream; discarding the remaining source blocks", gst_flow_get_name(ret), complete_str, source_block->block_nr);
			else
				GST_LOG_OBJECT(rs_fec_dec, "pushed %s source block #%u downstream", complete_str, source_block->block_nr);
		}

		gst_rs_fec_dec_destroy_source_block(rs_fec_dec, source_block);
	}

	/* All done. Destroy block list. */
	g_slist_free(drain_block_list);

	return ret;
}


static void gst_rs_fec_dec_reset_states(GstRSFECDec *rs_fec_dec)
{
	/* _Not_ setting encoding_symbol_length to 0 here, since its
	 * size also defines the size of the symbol memory blocks.
	 * These shall only be reallocated if the encoding_symbol_length
	 * changes. If encoding_symbol_length is set to 0 here, it means
	 * the memory blocks would have to be deallocated here as
	 * well, which is a waste if future incoming blocks happen to
	 * have the same encoding symbol length as the past ones. */

	rs_fec_dec->first_adu = TRUE;
	rs_fec_dec->first_pruning = TRUE;
	rs_fec_dec->segment_started = FALSE;
	rs_fec_dec->fecsource_eos = FALSE;
	rs_fec_dec->fecrepair_eos = FALSE;
}


static void gst_rs_fec_dec_flush(GstRSFECDec *rs_fec_dec)
{
	GHashTableIter iter;
	gpointer value;

	/* Cleanup any leftover source blocks */
	g_hash_table_iter_init(&iter, rs_fec_dec->source_block_table);
	while (g_hash_table_iter_next(&iter, NULL, &value))
	{
		GstRSFECDecSourceBlock *source_block = (GstRSFECDecSourceBlock *)value;
		gst_rs_fec_dec_destroy_source_block(rs_fec_dec, source_block);
		g_hash_table_iter_remove(&iter);
	}

	gst_rs_fec_dec_reset_states(rs_fec_dec);
}


static GstFlowReturn gst_rs_fec_dec_push_adu(GstRSFECDec *rs_fec_dec, GstBuffer *adu)
{
	if (rs_fec_dec->do_timestamp)
	{
		/* Fetch clock and base time, to be able to set buffer timestamps */
		GstClock *clock = GST_ELEMENT_CLOCK(rs_fec_dec);
		GstClockTime base_time = GST_ELEMENT_CAST(rs_fec_dec)->base_time;

		/* Set the buffer PTS and DTS to the current running time */
		if (clock != NULL)
		{
			GstClockTime ts;
			GstClockTime now = gst_clock_get_time(clock);
			ts = now - base_time;
			GST_BUFFER_PTS(adu) = ts;
			GST_BUFFER_DTS(adu) = ts;
		}
	}

	return gst_pad_push(rs_fec_dec->srcpad, adu);
}


static void gst_rs_fec_dec_push_stream_start(GstRSFECDec *rs_fec_dec)
{
	GstEvent *event;
	gchar stream_id[32];

	/* Catch redundant calls */
	if (rs_fec_dec->stream_started)
		return;

	g_snprintf(stream_id, sizeof(stream_id), "rsfecdec-%08x", g_random_int());
	GST_DEBUG_OBJECT(rs_fec_dec, "sending out stream-start event with ID %s", stream_id);

	event = gst_event_new_stream_start(stream_id);
	gst_pad_push_event(rs_fec_dec->srcpad, event);

	rs_fec_dec->stream_started = TRUE;
}


static void gst_rs_fec_dec_push_segment(GstRSFECDec *rs_fec_dec)
{
	GstEvent *event;
	GstSegment segment;

	/* Catch redundant calls */
	if (rs_fec_dec->segment_started)
		return;

	gst_segment_init(&segment, GST_FORMAT_TIME);

	GST_DEBUG_OBJECT(rs_fec_dec, "sending out segment event");

	event = gst_event_new_segment(&segment);
	gst_pad_push_event(rs_fec_dec->srcpad, event);

	rs_fec_dec->segment_started = TRUE;
}


static void gst_rs_fec_dec_push_eos(GstRSFECDec *rs_fec_dec)
{
	/* Only push EOS downstream if both sinkpads received EOS.
	 * For example, if the fecsource sinkpad gets EOS, it may
	 * still be possible for the fecrepair sinkpad to receive
	 * enough repair symbols to recover some ADUs.
	 * Exception: if num_repair_symbols is 0, then no repair
	 * symbols are expected, so just look at fecsource_eos
	 * in that case. */
	if (rs_fec_dec->fecsource_eos && (rs_fec_dec->fecrepair_eos || (rs_fec_dec->num_repair_symbols == 0)))
	{
		GST_DEBUG_OBJECT(rs_fec_dec, "both sinkpads received EOS -> draining source block table and pushing EOS downstream");

		/* Send stream-start and segment events if necessary */
		gst_rs_fec_dec_push_stream_start(rs_fec_dec);
		gst_rs_fec_dec_push_segment(rs_fec_dec);

		gst_rs_fec_dec_drain_source_block_table(rs_fec_dec);

		gst_pad_push_event(rs_fec_dec->srcpad, gst_event_new_eos());
	}
}


static of_session_t* gst_rs_fec_dec_create_openfec_session(GstRSFECDec *rs_fec_dec, gsize encoding_symbol_length)
{
	of_status_t status;
	of_session_t *session;
	of_rs_parameters_t params;

	/* NOTE: This code (and in fact the entire element) assumes the number of
	 * source and repair symbols per source block does not change during a
	 * session. Also see the checks in set_property(). */

	/* Create the session */
	if ((status = of_create_codec_instance(&session, OF_CODEC_REED_SOLOMON_GF_2_8_STABLE, OF_DECODER, 0)) != OF_STATUS_OK)
	{
		GST_ERROR_OBJECT(rs_fec_dec, "could not create codec instance: %s", gst_rs_fec_dec_get_status_name(status));
		CHECK_IF_FATAL_ERROR(rs_fec_dec, status);
		return NULL;
	}

	/* Install our source symbol callback
	 * This callback returns memory blocks from the allocated_encoding_symbol_table,
	 * making sure these preallocated blocks are used, instead of having OpenFEC
	 * allocate blocks */
	of_set_callback_functions(session, gst_rs_fec_dec_openfec_source_symbol_cb, NULL, rs_fec_dec);

	GST_LOG_OBJECT(rs_fec_dec, "configuring OpenFEC decoder session  (num source symbols: %u  num repair symbols: %u  encoding symbol length: %" G_GSIZE_FORMAT ")", rs_fec_dec->num_source_symbols, rs_fec_dec->num_repair_symbols, encoding_symbol_length);

	memset(&params, 0, sizeof(params));
	params.nb_source_symbols = rs_fec_dec->num_source_symbols;
	params.nb_repair_symbols = rs_fec_dec->num_repair_symbols;
	params.encoding_symbol_length = encoding_symbol_length;

	/* Instruct the OpenFEC session to (re)configure itself */
	if ((status = of_set_fec_parameters(session, (of_parameters_t *)(&params))) != OF_STATUS_OK)
	{
		GST_ERROR_OBJECT(rs_fec_dec, "could not set FEC parameters: %s", gst_rs_fec_dec_get_status_name(status));
		of_release_codec_instance(session);
		CHECK_IF_FATAL_ERROR(rs_fec_dec, status);
		return NULL;
	}

	/* If the encoding_symbol_length changed since the last time,
	 * the symbol memory blocks have to be reallocated.
	 * NOTE: if this is the first time gst_rs_fec_dec_create_openfec_session()
	 * is called after allocating the encoding symbol tables, it must be
	 * ensured that rs_fec_dec->encoding_symbol_length is 0, since in that
	 * case, there won't be any symbol memory blocks present yet */
	if (rs_fec_dec->encoding_symbol_length != encoding_symbol_length)
	{
		guint i;

		GST_DEBUG_OBJECT(rs_fec_dec, "encoding symbol length changed from %" G_GSIZE_FORMAT " to %" G_GSIZE_FORMAT "; need to reallocate symbol memory blocks", rs_fec_dec->encoding_symbol_length, encoding_symbol_length);

		/* Deallocate any existing symbol memory blocks, but do NOT deallocate the
		 * table itself (unlike in gst_rs_fec_dec_free_encoding_symbol_table() )
		 * It is still needed */
		if (rs_fec_dec->encoding_symbol_length != 0)
		{
			for (i = 0; i < rs_fec_dec->num_source_symbols; ++i)
				g_slice_free1(rs_fec_dec->encoding_symbol_length, rs_fec_dec->allocated_encoding_symbol_table[i]);
		}

		/* Allocate a new set of memory blocks with the new encoding symbol length each.
		 * Only the source symbols are allocated. The repair symbols do not need
		 * allocation, since they can be read from the FEC repair packets directly. */
		for (i = 0; i < rs_fec_dec->num_source_symbols; ++i)
			rs_fec_dec->allocated_encoding_symbol_table[i] = g_slice_alloc(encoding_symbol_length);

		/* Set the new encoding symbol length */
		rs_fec_dec->encoding_symbol_length = encoding_symbol_length;
	}

	return session;
}


static void* gst_rs_fec_dec_openfec_source_symbol_cb(void *context, G_GNUC_UNUSED UINT32 size, UINT32 esi)
{
	/* Callback invoked by the OpenFEC of_finish_decoding() function.
	 * See the comments in gst_rs_fec_dec_process_source_block() for
	 * further details. */

	GstRSFECDec *rs_fec_dec = (GstRSFECDec *)(context);
	GST_LOG_OBJECT(rs_fec_dec, "returning pointer to allocated symbol memory block for ESI %u", esi);
	return rs_fec_dec->allocated_encoding_symbol_table[esi];
}


static gchar const * gst_rs_fec_dec_get_status_name(of_status_t status)
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
