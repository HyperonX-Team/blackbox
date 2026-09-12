Name:           blackbox
Version:        @VERSION@
Release:        1
Summary:        Download a machine, in one file
License:        Apache-2.0
URL:            https://github.com/HyperonX-Team/blackbox
BuildArch:      @ARCH@
Requires:       glibc

%description
Blackbox packs an application together with its runtime, dependencies,
interface and permissions into a single portable, reproducible .blackbox
file. Recipients need nothing installed.

This package installs the command line tool and the desktop application
into /usr/bin.

%prep
# no source to unpack: the binaries are supplied in the build sources

%build
# nothing to compile

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
install -m 0755 %{_sourcedir}/blackbox     %{buildroot}%{_bindir}/blackbox
install -m 0755 %{_sourcedir}/blackbox-gui %{buildroot}%{_bindir}/blackbox-gui
mkdir -p %{buildroot}%{_datadir}/applications
install -m 0644 %{_sourcedir}/blackbox-gui.desktop %{buildroot}%{_datadir}/applications/blackbox-gui.desktop
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
install -m 0644 %{_sourcedir}/blackbox.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/blackbox.svg

%files
%{_bindir}/blackbox
%{_bindir}/blackbox-gui
%{_datadir}/applications/blackbox-gui.desktop
%{_datadir}/icons/hicolor/scalable/apps/blackbox.svg

%changelog
* Thu Jan 01 2026 The Blackbox Project <kareemharimech7@gmail.com> - @VERSION@-1
- Packaged release @VERSION@
