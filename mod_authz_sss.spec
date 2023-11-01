%{!?_httpd_mmn: %{expand: %%global _httpd_mmn %%(cat %{_includedir}/httpd/.mmn || echo 0-0)}}
%{!?_httpd_apxs:       %{expand: %%global _httpd_apxs       %%{_sbindir}/apxs}}
%{!?_httpd_confdir:    %{expand: %%global _httpd_confdir    %%{_sysconfdir}/httpd/conf.d}}
# /etc/httpd/conf.d with httpd < 2.4 and defined as /etc/httpd/conf.modules.d with httpd >= 2.4
%{!?_httpd_modconfdir: %{expand: %%global _httpd_modconfdir %%{_sysconfdir}/httpd/conf.d}}
%{!?_httpd_moddir:    %{expand: %%global _httpd_moddir    %%{_libdir}/httpd/modules}}

Summary: Apache module to authorize authenticated user based on SSSD groups he is member of
Name: mod_authz_sss
Version: 1.0.0
Release: 1%{?dist}
License: ASL 2.0
Group: System Environment/Daemons
URL: 
Source0: 
BuildRequires: httpd-devel
BuildRequires: dbus-devel
BuildRequires: pkgconfig
Requires: httpd-mmn = %{_httpd_mmn}

# Suppres auto-provides for module DSO per
# https://fedoraproject.org/wiki/Packaging:AutoProvidesAndRequiresFiltering#Summary
%{?filter_provides_in: %filter_provides_in %{_libdir}/httpd/modules/.*\.so$}
%{?filter_setup}

%description
mod_authz_sss can retrieve posix or non posix groups about the authenticated user and use it for 
access authorization

%prep
%setup -q -n %{name}-%{version}

%build
%{_httpd_apxs} -c -Wc,"%{optflags} -Wall -pedantic -std=c99 $(pkg-config --cflags dbus-1)" $(pkg-config --libs dbus-1) mod_authz_sss.c
%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
echo > authz_sss.confx
echo "# Load the module in %{_httpd_modconfdir}/55-authz_sss.conf" >> authz_sss.confx
cat authz_sss.conf >> authz_sss.confx
%else
cat authz_sss.module > authz_sss.confx
cat authz_sss.conf >> authz_sss.confx
%endif

%install
rm -rf $RPM_BUILD_ROOT
install -Dm 755 .libs/mod_authz_sss.so $RPM_BUILD_ROOT%{_httpd_moddir}/mod_authz_sss.so

%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
# httpd >= 2.4.x
install -Dp -m 0644 authz_sss.module $RPM_BUILD_ROOT%{_httpd_modconfdir}/55-authz_sss.conf
%endif
install -Dp -m 0644 authz_sss.confx $RPM_BUILD_ROOT%{_httpd_confdir}/authz_sss.conf

%files
%doc README LICENSE
%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
%config(noreplace) %{_httpd_modconfdir}/55-authz_sss.conf
%endif
%config(noreplace) %{_httpd_confdir}/authz_sss.conf
%{_httpd_moddir}/*.so

%changelog
* Thu Aug 31 2023 Ondrej Valousek <ondrej.valousek.xm@renesas.com> - 1.0.0
- Initial release.
