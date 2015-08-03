/* GStreamer plugin containing elements for FECFRAME-based forward error correction
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


#include <gst/gst.h>
#include "reed-solomon/gstrsfecenc.h"
#include "reed-solomon/gstrsfecdec.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


static gboolean plugin_init(GstPlugin *plugin)
{
	gboolean ret = TRUE;
	ret = ret && gst_element_register(plugin, "rsfecenc", GST_RANK_NONE, gst_rs_fec_enc_get_type());
	ret = ret && gst_element_register(plugin, "rsfecdec", GST_RANK_NONE, gst_rs_fec_dec_get_type());
	return ret;
}


GST_PLUGIN_DEFINE(
	GST_VERSION_MAJOR,
	GST_VERSION_MINOR,
	gstfecframe,
	"en- and decoder elements implementing FECFRAME-compatible forward error correction",
	plugin_init,
	VERSION,
	"LGPL",
	GST_PACKAGE_NAME,
	GST_PACKAGE_ORIGIN
)
