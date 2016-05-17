%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}-%{version}}

%if %{?fedora}%{!?fedora:0} >= 21 || %{?rhel}%{!?rhel:0} >= 7
%global use_systemd 1
%else
%global use_systemd 0
%endif

Summary:	xrootd-aggregatingname2name 
Name:		xrootd-aggregatingname2name
Version:	1.0.1
Epoch:		1
Release:	1%{?dist}
License:	none
Group:		System Environment/Daemons

Source0: 	%{name}-%{version}.tar.gz
BuildRoot: 	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires: xrootd-server >= 4.0.0 , xrootd-client >= 4.0.0

%ifarch x86_64
  %define __lib lib64
%else
  %define __lib lib
%endif

%define __prefix /usr/
%define __libdir /usr/%{__lib}/
%define __incdir /usr/include/
%define __xrootddir /usr/

%description
xrootd-aggregatingname2name

%prep
%setup -q

%build
./configure --prefix=%{__prefix} --libdir=%{__libdir} --with-xrootd-location=%{__xrootddir}
make %{?_smp_mflags}

%install
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT \( -type f -o -type l \) -print | sed "s#^$RPM_BUILD_ROOT/*#/#" > RPM-FILE-LIST

%clean
rm -rf $RPM_BUILD_ROOT

%files -f RPM-FILE-LIST
%defattr(-,root,root)

%changelog
* Tue Jun 16 2015 adrian <adrian.sevcenco@cern.ch> - xrootd-aggregatingname2name
- Initial build.