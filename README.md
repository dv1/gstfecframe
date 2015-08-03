gstfecframe - GStreamer en- and decoder elements implementing FECFRAME-compatible forward error correction
==========================================================================================================

About
-----

This is a plugin containing elements which implement [FECFRAME RFCs](https://tools.ietf.org/wg/fecframe/)
for application-level forward error correction, or more precisely, erasure coding.

These elements do not check for data corruption in received packets. Received packets are assumed to
have been verified by the underlying transport layer. On the application level, a received packet is
either intact, or missing.


License
-------

This plugin is licensed under the LGPL v2.


Dependencies
------------

gstfecframe makes use of the [OpenFEC library](http://openfec.org/) for recovering lost data.
Version 1.4.2 or newer is needed.


Elements
--------

Currently, these elements are implemented:

* `rsfecenc` & `rsfecdec` : en- and decoder based on RFC 6865 for Reed-Solomon erasure coding


Building and installing
-----------------------

This project uses the [waf meta build system](https://code.google.com/p/waf/). To configure, first set
the following environment variables to whatever is necessary for cross compilation for your platform:

* `CC`
* `CXX`
* `CFLAGS`
* `CXXFLAGS`
* `LDFLAGS`
* `PKG_CONFIG_PATH`
* `PKG_CONFIG_SYSROOT_DIR`

Then, run:

    ./waf configure --prefix=PREFIX --openfec-include-path=OPENFEC_INCLUDE_PATH --openfec-lib-path=OPENFEC_LIB_PATH

(The aforementioned environment variables are only necessary for this configure call.)
PREFIX defines the installation prefix, that is, where the built binaries will be installed.

Since OpenFEC has no default installation paths so far, the paths to its headers and libraries
have to be set explicitely. `--openfec-include-path` must be set to the path where the
`of_openfec_api.h` header is located. `--openfec-lib-path` must be set to the path where
the OpenFEC libraries are located. For example, if OpenFEC 1.4.2 was built in debug mode,
and it is located in `/home/user/openfec_v1.4.2`, the command-line switches are set to:

    --openfec-include-path=/home/user/openfec_v1.4.2/src/lib_common --openfec-lib-path=/home/user/openfec_v1.4.2/bin/Debug

Additional optional configuration switches are:

* `--enable-debug` : adds debug compiler flags to the build
* `--with-package-name` : name that shall be used for this package
* `--with-package-origin` : origin URL that shall be used for this package
* `--plugin-install-path` : where to install the plugin (by default, it will install in `${PREFIX}/lib/gstreamer-1.0`)

The package name and -origin switches are useful for distribution package builders,
which can specify a distribution specific name and URL.

Once configuration is complete, run:

    ./waf

This builds the plugin.
Finally, to install, run:

    ./waf install


Example pipelines
-----------------

This pipeline produces a sine signal, encodes the buffers to produce FEC packets, drops 50% of all FEC source packets (simulating a very lossy channel), and tries to recover data from the remaining FEC packets:

    gst-launch-1.0 audiotestsrc samplesperbuffer=882 is-live=true ! "audio/x-raw, format=S16LE, rate=44100, channels=1" ! rsfecenc num-source-symbols=5 num-repair-symbols=3 name=fecenc  \
                   rsfecdec num-source-symbols=5 num-repair-symbols=3 name=fecdec ! "audio/x-raw, format=S16LE, rate=44100, channels=1" ! autoaudiosink  \
                   fecenc.fecrepair ! queue ! fecdec.fecrepair  \
                   fecenc.fecsource ! queue ! identity drop-probability=0.5 ! fecdec.fecsource

Setting the `num-repair-symbols` properties from 3 to 0 disables recoveries, equaling a transmission without FEC. The amount of gaps is much higher compared to when the property is set to 3.


Limitations
-----------

* Multiple ADU flows are currently unsupported. Multiple flows require substantial
  changes. Support is planned for a future version, which will be based on the
  [GstAggregator base class](http://gstreamer.freedesktop.org/data/doc/gstreamer/head/gst-plugins-bad-libs/html/gst-plugins-bad-libs-GstAggregator.html)
  which debuted in GStreamer 1.5, and will require more support for real-time
  characteristics of individual flows.
* Special RTP support in the Reed-Solomon elements is currently missing.
* The strict mode described in RFC 6865 is not implemented, since it can be done
  effectively outside of the `rsfecdec` element by using a pad probe and checking
  the size of the outgoing ADUs.
* The number of repair and source symbols in the Reed-Solomon elements cannot be
  changed once a stream starts.
