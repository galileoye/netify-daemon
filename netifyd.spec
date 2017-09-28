# Netify DPI Daemon

Name: netifyd
Version: 1.21
Release: 1%{dist}
Vendor: eGloo Incorporated
License: GPL
Group: System/Daemons
Packager: eGloo Incorporated
Source: %{name}-%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-%{version}
Obsoletes: cdpid
BuildRequires: autoconf >= 2.63
BuildRequires: automake
BuildRequires: bc
BuildRequires: json-c-devel
BuildRequires: libcurl-devel
BuildRequires: libmnl-devel
BuildRequires: libnetfilter_conntrack-devel
BuildRequires: libpcap-devel
BuildRequires: libtool
BuildRequires: ncurses-devel
BuildRequires: pkgconfig
BuildRequires: zlib-devel
%if "0%{dist}" == "0.v7"
Requires: app-network-core
Requires: ncurses
Requires: webconfig-httpd
%{?systemd_requires}
BuildRequires: systemd
%endif
Summary: Netify DPI Daemon

%description
Netify provides visibility into the traffic on your network along with the option to take an active role (on supported devices) in stopping/shaping undesirable traffic from recurring on your network.
Report bugs to: https://github.com/eglooca/netify-daemon/issues

# Prepare
%prep
%setup -q
./autogen.sh
export CFLAGS="-I /usr/include/libnfnetlink-1.0.1"
export CXXFLAGS="-I /usr/include/libnfnetlink-1.0.1"
export LIBS="/usr/local/lib/libnfnetlink.a"
export LIBMNL_CFLAGS="-I /usr/local/include"
export LIBMNL_LIBS="/usr/local/lib/libmnl.a"
export LIBNETFILTER_CONNTRACK_CFLAGS="-I /usr/local/include"
export LIBNETFILTER_CONNTRACK_LIBS="/usr/local/lib/libnetfilter_conntrack.a"
%{configure}

# Build
%build
make %{?_smp_mflags}

# Install
%install
make install DESTDIR=%{buildroot}
rm -rf %{buildroot}/%{_libdir}
rm -rf %{buildroot}/%{_includedir}
rm -rf %{buildroot}/%{_bindir}
mkdir -p %{buildroot}/%{_sharedstatedir}/%{name}
mkdir -p %{buildroot}/%{_sysconfdir}

%if "0%{dist}" == "0.v7"
install -D -m 0644 deploy/clearos/%{name}.tmpf %{buildroot}/%{_tmpfilesdir}/%{name}.conf
install -D -m 0660 deploy/clearos/%{name}.conf %{buildroot}/%{_sysconfdir}/%{name}.conf
install -D -m 0755 deploy/clearos/exec-pre.sh %{buildroot}/%{_libexecdir}/%{name}/exec-pre.sh
install -D -m 644 deploy/%{name}.service %{buildroot}/%{_unitdir}/%{name}.service
mkdir -p %{buildroot}/run
install -d -m 0755 %{buildroot}/run/%{name}
%endif

%if "0%{dist}" == "0.v6"
install -D -m 0660 deploy/clearos/%{name}.conf %{buildroot}/%{_sysconfdir}/%{name}.conf
install -D -m 0755 deploy/clearos/%{name}.init %{buildroot}/%{_sysconfdir}/init.d/%{name}
mkdir -p %{buildroot}/var/run
install -d -m 0755 %{buildroot}/var/run/%{name}
%endif

install -D -m 0644 deploy/app-custom-match.conf %{buildroot}/%{_sharedstatedir}/%{name}/app-custom-match.conf

#install -D -m 0644 deploy/%{name}.tmpf %{buildroot}/%{_tmpfilesdir}/%{name}.conf
#install -D -m 0660 deploy/%{name}.conf %{buildroot}/%{_sysconfdir}/%{name}.conf
#install -D -m 0755 deploy/exec-pre.sh %{buildroot}/%{_libexecdir}/%{name}/exec-pre.sh
#install -D -m 644 deploy/%{name}.service %{buildroot}/%{_unitdir}/%{name}.service
#mkdir -p %{buildroot}/run
#install -d -m 0755 %{buildroot}/run/%{name}

# Clean-up
%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

# Post install
%post
%if "0%{dist}" == "0.v7"
%systemd_post %{name}.service
%endif

uuid=$(egrep '^uuid' %{_sysconfdir}/%{name}.conf | sed -e "s/^uuid[[:space:]]*=[[:space:]]*\([A-NP-Z0-9-]*\)$/\1/")
if [ -z "$uuid" -o "$uuid" == "00-00-00-00" ]; then
    uuid=$(%{_sbindir}/%{name} -U 2>/dev/null)
    if [ -z "$uuid" ]; then
        echo "Error generating UUID."
    else
        sed -e "s/^uuid[[:space:]]*=[[:space:]]*00-00-00-00/uuid = $uuid/" -i %{_sysconfdir}/%{name}.conf
    fi
fi

if [ ! -z "$uuid" ]; then
    echo "Your Netify Site UUID is: $(tput smso)$uuid$(tput rmso)"
    echo "Follow this link to provision your site: https://www.egloo.ca/login"
fi

rm -f %{_sharedstatedir}/%{name}/*.csv

# Pre uninstall
%preun
%if "0%{dist}" == "0.v7"
%systemd_preun %{name}.service
%endif

# Post uninstall
%postun
%if "0%{dist}" == "0.v7"
%systemd_postun_with_restart %{name}.service
%endif

# Files
%files
%defattr(-,root,root)
%if "0%{dist}" == "0.v6"
%dir /var/run/%{name}
%attr(755,root,root) %{_sysconfdir}/init.d/%{name}
%endif
%if "0%{dist}" == "0.v7"
%attr(644,root,root) %{_tmpfilesdir}/%{name}.conf
%attr(644,root,root) %{_unitdir}/%{name}.service
%attr(755,root,root) %{_libexecdir}/%{name}/
%dir /run/%{name}
%endif
%dir %attr(750,root,webconfig) %{_sharedstatedir}/%{name}/
%attr(640,root,webconfig) %{_sharedstatedir}/%{name}/app-custom-match.conf
%config(noreplace) %attr(660,root,webconfig) %{_sysconfdir}/%{name}.conf
%{_sbindir}/%{name}
%{_mandir}/man5/*
%{_mandir}/man8/*

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
