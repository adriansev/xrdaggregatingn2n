Summary:  xrootd-aggregatingname2name
Name: xrootd-aggregatingname2name
Version:  1.0.1
Release:  3%{?dist}
License:  none
Group:  System Environment/Daemons

Source0:  %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

Requires: xrootd-server >= 4.0.0 , xrootd-client >= 4.0.0

%define __xrootddir /usr/

%description
xrootd-aggregatingname2name

%prep
%setup -q
./bootstrap.sh

%build
./configure --prefix=%{_prefix} --libdir=%{_libdir} --with-xrootd-location=%{__xrootddir}
make %{?_smp_mflags}

%install
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -name "*.la" -delete
find $RPM_BUILD_ROOT \( -type f -o -type l \) -print | sed "s#^$RPM_BUILD_ROOT/*#/#" > RPM-FILE-LIST

%clean
rm -rf $RPM_BUILD_ROOT

%files -f RPM-FILE-LIST
%defattr(-,root,root)

%changelog
* Tue Jun 16 2015 adrian <adrian.sevcenco@cern.ch> - xrootd-aggregatingname2name
- Initial build.

