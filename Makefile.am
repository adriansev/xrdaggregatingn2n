#######################################################################
## Makefile.am for alice name2name plugin
##
##
## Version info: $Id: Makefile.am,v 1.5 2006/07/24 07:38:57 dfeich Exp $
## Checked in by $Author: dfeich $
#######################################################################

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libXrdAggregatingName2Name.la
AM_CPPFLAGS = -I$(XROOTD_LOCATION)/src -I$(XROOTD_LOCATION)/include/xrootd

###############################################

libXrdAggregatingName2Name_la_SOURCES = XrdAggregatingName2Name.cc

nodist_libXrdAggregatingName2Name_la_SOURCES = $(OFSSOURCES)

libXrdAggregatingName2Name_la_LIBADD = -L$(XROOTD_LOCATION)/lib$(MARK64)/ -lXrdUtils

EXTRA_DIST = configure.ac bootstrap.sh

