#!/usr/bin/env python


from waflib.Build import BuildContext, CleanContext, InstallContext, UninstallContext, Logs

top = '.'
out = 'build'

gstimx_version = "0.10.1"

# the code inside fragment deliberately does an unsafe implicit cast float->char to trigger a
# compiler warning; sometimes, gcc does not tell about an unsupported parameter *unless* the
# code being compiled causes a warning
c_cflag_check_code = """
int main()
{
	float f = 4.0;
	char c = f;
	return c - 4;
}
"""
def check_compiler_flag(conf, flag, lang):
	return conf.check(fragment = c_cflag_check_code, mandatory = 0, execute = 0, define_ret = 0, msg = 'Checking for compiler switch %s' % flag, cxxflags = conf.env[lang + 'FLAGS'] + [flag], okmsg = 'yes', errmsg = 'no')  
def check_compiler_flags_2(conf, cflags, ldflags, msg):
	Logs.pprint('NORMAL', msg)
	return conf.check(fragment = c_cflag_check_code, mandatory = 0, execute = 0, define_ret = 0, msg = 'Checking if building with these flags works', cxxflags = cflags, ldflags = ldflags, okmsg = 'yes', errmsg = 'no')


def add_compiler_flags(conf, env, flags, lang, compiler, uselib = ''):
	for flag in reversed(flags):
		if type(flag) == type(()):
			flag_candidate = flag[0]
			flag_alternative = flag[1]
		else:
			flag_candidate = flag
			flag_alternative = None

		if uselib:
			flags_pattern = lang + 'FLAGS_' + uselib
		else:
			flags_pattern = lang + 'FLAGS'

		if check_compiler_flag(conf, flag_candidate, compiler):
			env.prepend_value(flags_pattern, [flag_candidate])
		elif flag_alternative:
			if check_compiler_flag(conf, flag_alternative, compiler):
				env.prepend_value(flags_pattern, [flag_alternative])


def options(opt):
	opt.add_option('--enable-debug', action = 'store_true', default = False, help = 'enable debug build [default: %default]')
	opt.add_option('--with-package-name', action = 'store', default = "Unknown package release", help = 'specify package name to use in plugin [default: %default]')
	opt.add_option('--with-package-origin', action = 'store', default = "Unknown package origin", help = 'specify package origin URL to use in plugin [default: %default]')
	opt.add_option('--plugin-install-path', action = 'store', default = "${PREFIX}/lib/gstreamer-1.0", help = 'where to install the plugin for GStreamer 1.0 [default: %default]')
	opt.add_option('--openfec-include-path', action = 'store', default = "", help = 'path to the of_openfec_api.h header')
	opt.add_option('--openfec-lib-path', action = 'store', default = "", help = 'path to the libopenfec object')
	opt.load('compiler_c')
	opt.load('gnu_dirs')


def configure(conf):
	import os

	conf.load('compiler_c')
	conf.load('gnu_dirs')

	# check and add compiler flags

	if conf.env['CFLAGS']:
		check_compiler_flags_2(conf, conf.env['CFLAGS'], '', "Need to test C compiler flags %s" % ' '.join(conf.env['CFLAGS']))
	if conf.env['LINKFLAGS']:
		check_compiler_flags_2(conf, '', conf.env['LINKFLAGS'], "Need to test linker flags %s" % ' '.join(conf.env['LINKFLAGS']))

	c_compiler_flags = ['-Wextra', '-Wall', '-std=gnu89', '-fPIC', '-DPIC']
	if conf.options.enable_debug:
		c_compiler_flags += ['-O0', '-g3', '-ggdb']
	else:
		c_compiler_flags += ['-O2']

	add_compiler_flags(conf, conf.env, c_compiler_flags, 'C', 'C')


	# test for GStreamer libraries

	conf.check_cfg(package = 'gstreamer-1.0 >= 1.2.0', uselib_store = 'GSTREAMER', args = '--cflags --libs', mandatory = 1)
	conf.check_cfg(package = 'gstreamer-base-1.0 >= 1.2.0', uselib_store = 'GSTREAMER_BASE', args = '--cflags --libs', mandatory = 1)


	# OpenFEC

	conf.check_cc(mandatory = 1, lib = 'openfec', libpath = [conf.options.openfec_lib_path], uselib_store = 'OPENFEC')
	conf.check_cc(mandatory = 1, header_name = 'of_openfec_api.h', includes = [conf.options.openfec_include_path], uselib_store = 'OPENFEC')


	# misc definitions & env vars

	conf.env['PLUGIN_INSTALL_PATH'] = os.path.expanduser(conf.options.plugin_install_path)

	conf.define('GST_PACKAGE_NAME', conf.options.with_package_name)
	conf.define('GST_PACKAGE_ORIGIN', conf.options.with_package_origin)
	conf.define('PACKAGE', "gstfecframe")
	conf.define('VERSION', '1.0')


	conf.write_config_header('config.h')



def build(bld):
	source = bld.path.ant_glob('src/*.c') + \
	         bld.path.ant_glob('src/reed-solomon/*.c')
	bld(
		features = ['c', 'cshlib'],
		includes = ['.'],
		uselib = ['OPENFEC', 'GSTREAMER', 'GSTREAMER_BASE'],
		target = 'gstfecframe',
		defines = 'HAVE_CONFIG_H',
		source = source,
		install_path = bld.env['PLUGIN_INSTALL_PATH']
	)
