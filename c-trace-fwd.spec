%global forgeurl https://github.com/NadiaYvette/c-trace-fwd
%global branch   master
%forgemeta
Name:            c_trace_fwd
Version:         0.1.0
Release:         %autorelease
Summary:         C trace forwarder
License:         MIT
URL:             %{forgeurl}
Source0:         %{forgesource}
BuildRequires:   gcc, gdb, glib2-devel, texlive-xetex, libcbor-devel

%description
C trace forwarding library w/example executable

%prep
%forgeautosetup

%build
%make_build

%install
install -Dpm 755 obj/bin/c_trace_fwd -t %{buildroot}%{_bindir}
install -Dpm 755 obj/lib/libc_trace_fwd.so -t %{buildroot}%{_libdir}

%files
%{_bindir}/c_trace_fwd
%{_libdir}/libc_trace_fwd.so

%changelog
* Tue Sep 2 2025 Nadia Chambers <nadia.chambers@iohk.io> - 1.0-1
- First c_trace_fwd package
