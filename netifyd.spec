# Netify DPI Daemon

Name: netifyd
Version: 1.0
Release: 1%{dist}
Vendor: eGloo Incorporated
License: GPL
Group: System/Daemons
Packager: eGloo Incorporated
Source: %{name}-%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-%{version}
Obsoletes: cdpid
Requires: /usr/bin/systemctl
Requires: /usr/bin/uuidgen
%if "0%{dist}" == "0.v7"
Requires: webconfig-httpd
Requires: app-network-core
%endif
BuildRequires: autoconf >= 2.63
BuildRequires: automake
BuildRequires: pkgconfig
BuildRequires: libtool
BuildRequires: libpcap-devel
BuildRequires: json-c-devel
BuildRequires: libcurl
BuildRequires: zlib-devel
#BuildRequires: libmnl-devel
Summary: Netify DPI Daemon

%description
Netify DPI Daemon
Report bugs to: http://www.egloo.ca/bug_tracker

# Build
%prep
%setup -q
./autogen.sh
ac_flags="--with-pic=inih --with-pic=ndpi"
%if "0%{dist}" == "0.v7"
ac_flags="$ac_flags --enable-cloud-sync"
%endif
%{configure} $ac_flags
%build
make %{?_smp_mflags}

# Install
%install
make install DESTDIR=%{buildroot}
rm -rf %{buildroot}/%{_libdir}
rm -rf %{buildroot}/%{_includedir}
rm -rf %{buildroot}/%{_bindir}
mkdir -vp %{buildroot}/%{_sharedstatedir}/%{name}
mkdir -vp %{buildroot}/%{_sysconfdir}
install -D -m 755 deploy/exec-pre.sh %{buildroot}/%{_libexecdir}/%{name}/exec-pre.sh
install -D -m 644 deploy/%{name}.service %{buildroot}/lib/systemd/system/%{name}.service
%if "0%{dist}" == "0.v7"
install -D -m 644 deploy/%{name}.tmpf-clearos %{buildroot}/%{_tmpfilesdir}/%{name}.conf
%else
install -D -m 644 deploy/%{name}.tmpf %{buildroot}/%{_tmpfilesdir}/%{name}.conf
%endif
install -D -m 660 deploy/%{name}.conf %{buildroot}/%{_sysconfdir}/%{name}.conf

# Clean-up
%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

# Post install
%post
if `egrep -q '^uuid[[:space:]]*=[[:space:]]*0$' %{_sysconfdir}/%{name}.conf 2>/dev/null`; then
    uuid=$(/usr/bin/uuidgen | tail -c 6)
    sed -e "s/^uuid[[:space:]]*=[[:space:]]*0/uuid = $uuid/" -i %{_sysconfdir}/%{name}.conf
fi

/usr/bin/systemctl enable %{name}.service -q
/usr/bin/systemctl restart %{name} -q

# Post uninstall
%postun
/usr/bin/systemctl stop %{name} -q
/usr/bin/systemctl disable %{name}.service -q

# Files
%files
%defattr(-,root,root)
%{_sbindir}/%{name}
%attr(750,root,webconfig) %{_sharedstatedir}/%{name}/
%attr(755,root,root) %{_libexecdir}/%{name}/
%attr(755,root,root) /lib/systemd/system
%attr(755,root,root) %{_tmpfilesdir}
%attr(755,root,root) %{_sysconfdir}
%config(noreplace) %attr(660,root,webconfig) %{_sysconfdir}/%{name}.conf

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4