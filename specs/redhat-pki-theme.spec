# Optionally fetch the release from the environment variable 'PKI_RELEASE'
%define use_pki_release %{getenv:USE_PKI_RELEASE}
%if 0%{?use_pki_release}
%define pki_release %{getenv:PKI_RELEASE}
%endif

Name:             redhat-pki-theme
%if 0%{?rhel}
Version:                10.5.18
%define redhat_release  10
%define redhat_stage    0
%define default_release %{redhat_release}.%{redhat_stage}
#%define default_release %{redhat_release}
%else
Version:                10.5.18
%define fedora_release  10
%define fedora_stage    0
%define default_release %{fedora_release}.%{fedora_stage}
#%define default_release %{fedora_release}
%endif

%if 0%{?use_pki_release}
#Release:          %{pki_release}%{?dist}
Release:          %{pki_release}.el7pki
%else
#Release:          %{default_release}%{?dist}
Release:          %{default_release}.el7pki
%endif

Summary:          Certificate System - Red Hat PKI Theme Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    git
BuildRequires:    java-1.8.0-openjdk-devel
BuildRequires:    jpackage-utils >= 1.7.5-10

%if 0%{?rhel}
# NOTE:  In the future, as a part of its path, this URL will contain a release
#        directory which consists of the fixed number of the upstream release
#        upon which this tarball was originally based.
Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{version}/%{release}/rhel/%{name}-%{version}%{?prerel}.tar.gz
%else
Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{version}/%{release}/%{name}-%{version}%{?prerel}.tar.gz
%endif

#Patch0:  redhat-pki-theme-rhel-7-9-rhcs-9-7-1.patch
#Patch1:  redhat-pki-theme-rhel-7-9-rhcs-9-7-bu-2.patch
#Patch2:  redhat-pki-theme-rhel-7-9-rhcs-9-7-bu-4.patch
#Patch3:  redhat-pki-theme-rhel-7-9-rhcs-9-7-bu-6.patch
#Patch4:  redhat-pki-theme-rhel-7-9-rhcs-9-7-bu-7.patch
#Patch5:  redhat-pki-theme-rhel-7-9-rhcs-9-7-bu-8.patch
#Patch6:  redhat-pki-theme-rhel-7-9-rhcs-9-7-bu-9.patch
#Patch7:  redhat-pki-theme-rhel-7-9-rhcs-9-7-bu-10.patch

%global overview                                                       \
Several PKI packages utilize a "virtual" theme component.  These       \
"virtual" theme components are "Provided" by various theme "flavors"   \
including "redhat" or a user customized theme package.  Consequently,  \
all "redhat" and any customized theme components MUST be mutually      \
exclusive!                                                             \
%{nil}

%description %{overview}


%package -n       redhat-pki-server-theme
Summary:          Certificate System - PKI Server Framework User Interface
Group:            System Environment/Base

Obsoletes:        redhat-pki-common-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-common-ui
Obsoletes:        redhat-pki-ca-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-ca-ui
Obsoletes:        redhat-pki-kra-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-kra-ui
Obsoletes:        redhat-pki-ocsp-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-ocsp-ui
Obsoletes:        redhat-pki-tks-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-tks-ui
Obsoletes:        redhat-pki-ra-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-ra-ui
Obsoletes:        redhat-pki-tps-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-tps-ui

Provides:         redhat-pki-common-theme = %{version}-%{release}
Provides:         pki-server-theme = %{version}-%{release}
Provides:         pki-common-theme = %{version}-%{release}
Provides:         pki-common-ui = %{version}-%{release}

Provides:         redhat-pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-ui = %{version}-%{release}

Provides:         redhat-pki-kra-theme = %{version}-%{release}
Provides:         pki-kra-theme = %{version}-%{release}
Provides:         pki-kra-ui = %{version}-%{release}

Provides:         redhat-pki-ocsp-theme = %{version}-%{release}
Provides:         pki-ocsp-theme = %{version}-%{release}
Provides:         pki-ocsp-ui = %{version}-%{release}

Provides:         redhat-pki-tks-theme = %{version}-%{release}
Provides:         pki-tks-theme = %{version}-%{release}
Provides:         pki-tks-ui = %{version}-%{release}

Provides:         redhat-pki-tps-theme = %{version}-%{release}
Provides:         pki-tps-theme = %{version}-%{release}
Provides:         pki-tps-ui = %{version}-%{release}

%description -n   redhat-pki-server-theme
This PKI Server Framework User Interface contains
the Red Hat textual and graphical user interface for the PKI Server Framework.

This package is used by the Red Hat Certificate System.

%{overview}


%package -n       redhat-pki-console-theme
Summary:          Certificate System - PKI Console User Interface
Group:            System Environment/Base

Requires:         java-1.8.0-openjdk

%if 0%{?rhel}
# EPEL version of Red Hat "theme" conflicts with all versions of Dogtag "theme"
Conflicts:        dogtag-pki-console-theme
Conflicts:        dogtag-pki-console-ui
%endif

Obsoletes:        redhat-pki-console-ui <= 9

Provides:         pki-console-theme = %{version}-%{release}
Provides:         pki-console-ui = %{version}-%{release}

%description -n   redhat-pki-console-theme
This PKI Console User Interface contains
the Red Hat textual and graphical user interface for the PKI Console.

This package is used by the Red Hat Certificate System.

%{overview}


# Replace "%setup -q -n %{name}-%{version}%{?prerel}" with "%autosetup -S git"
# in order to use "git apply <binary patch>" since "%patch0 -p1" doesn't
# support binary patches!
%prep


%autosetup -S git


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVERSION=%{version}-%{release} \
	-DVAR_INSTALL_DIR:PATH=/var \
	-DBUILD_REDHAT_PKI_THEME:BOOL=ON \
	-DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
	..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"


# NOTE:  Several "theme" packages require ownership of the "/usr/share/pki"
#        directory because the PKI subsystems (CA, KRA, OCSP, TKS, TPS)
#        which require them may be installed either independently or in
#        multiple combinations.

%files -n redhat-pki-server-theme
%defattr(-,root,root,-)
%doc redhat/common-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/CS_SERVER_VERSION
%{_datadir}/pki/common-ui/
%{_datadir}/pki/server/webapps/pki/ca
%{_datadir}/pki/server/webapps/pki/css
%{_datadir}/pki/server/webapps/pki/esc
%{_datadir}/pki/server/webapps/pki/fonts
%{_datadir}/pki/server/webapps/pki/images
%{_datadir}/pki/server/webapps/pki/kra
%{_datadir}/pki/server/webapps/pki/ocsp
%{_datadir}/pki/server/webapps/pki/pki.properties
%{_datadir}/pki/server/webapps/pki/tks


%files -n redhat-pki-console-theme
%defattr(-,root,root,-)
%doc redhat/console-ui/LICENSE
%{_javadir}/pki/


%changelog
* Sat Oct 23 2021 Dogtag Team <devel@lists.dogtagpki.org> 10.5.18-10
- Bugzilla Bug 2003855 - Update RHCS version of CA, KRA, OCSP, and TKS so
  that it can be identified using a browser [RHCS 9.7.z BU 10] (mharmsen)

* Wed Sep 15 2021 Dogtag Team <devel@lists.dogtagpki.org> 10.5.18-9
- Bugzilla Bug 2003854 - Update RHCS version of CA, KRA, OCSP, and TKS so
  that it can be identified using a browser [RHCS 9.7.z BU 9] (mharmsen)

* Mon Aug  9 2021 Dogtag Team <devel@lists.dogtagpki.org> 10.5.18-8
- Bugzilla Bug 1974464 - Update RHCS version of CA, KRA, OCSP, and TKS so
  that it can be identified using a browser [RHCS 9.7.z BU 8] (mharmsen)

* Fri Jun 25 2021 Dogtag Team <devel@lists.dogtagpki.org> 10.5.18-7
- Bugzilla Bug #1960688 - Update RHCS version of CA, KRA, OCSP, and TKS so
  that it can be identified using a browser [RHCS 9.7.z BU 7] (mharmsen)

* Thu Apr 22 2021 Dogtag Team <pki-devel@redhat.com> 10.5.18-6
- Bugzilla Bug #1952719 - Update RHCS version of CA, KRA, OCSP, and TKS so
  that it can be identified using a browser [RHCS 9.7.z BU 6] (mharmsen)

* Thu Feb 11 2021 Dogtag Team <pki-devel@redhat.com> 10.5.18-5
- Bugzilla Bug #1914474 - Update RHCS version of CA, KRA, OCSP, and TKS so
  that it can be identified using a browser [RHCS 9.7.z BU 4] (mharmsen)
- Update patternfly.css in Red Hat theme (ascheel, mharmsen)
- Update Patternfly fonts in Red Hat theme (ascheel, mharmsen)
- Add separate bootstrap CSS file in Red Hat theme (ascheel, mharmsen)

* Tue Nov 17 2020 Dogtag Team <pki-devel@redhat.com> 10.5.18-4
- Bugzilla Bug #1895104 - Update RHCS version of CA, KRA, OCSP, and TKS so
  that it can be identified using a browser [RHCS 9.7.z BU 2] (mharmsen)

* Wed Oct 14 2020 Dogtag Team <pki-devel@redhat.com> 10.5.18-3
- Bugzilla Bug #1887979 - Update RHCS version of CA, KRA, OCSP, and TKS so
  that it can be identified using a browser [RHCS 9.7.z BU 1] (mharmsen)

* Mon Apr  6 2020 Dogtag Team <pki-devel@redhat.com> 10.5.18-2
- Updated version number to 10.5.18-2

* Sun Mar 29 2020 Dogtag Team <pki-devel@redhat.com> 10.5.18-1
- Updated jss dependencies
- ##########################################################################
- # RHEL 7.9:
- ##########################################################################
- Bugzilla Bug #1774174 - Rebase pki-core from 10.5.17 to 10.5.18 (RHEL)
- ##########################################################################
- # RHCS 9.7:
- ##########################################################################
- Bugzilla Bug #1774177 - Rebase redhat-pki, redhat-pki-theme, pki-core, and
  pki-console to 10.5.18 in RHCS 9.7
- Bugzilla Bug #1774181 - Update RHCS version of CA, KRA, OCSP, and TKS so
  that it can be identified using a browser [RHCS]

* Tue Aug 13 2019 Dogtag Team <pki-devel@redhat.com> 10.5.17-1
- ##########################################################################
- # RHEL 7.8:
- ##########################################################################
- Bugzilla Bug #1733586 - Rebase pki-core from 10.5.16 to 10.5.17 (RHEL)
- ##########################################################################
- # RHCS 9.6:
- ##########################################################################
- Bugzilla Bug #1718418 - Update RHCS version of CA, KRA, OCSP, and TKS so
  that it can be identified using a browser [RHCS]
- Bugzilla Bug #1733588 - Rebase redhat-pki, redhat-pki-theme, pki-core, and
  pki-console to 10.5.17 in RHCS 9.6

* Thu Apr 18 2019 Dogtag Team <pki-devel@redhat.com> 10.5.16-2
- ##########################################################################
- # RHEL 7.7:
- ##########################################################################
- Bugzilla Bug #1633422 - Rebase pki-core from 10.5.9 to 10.5.16 (RHEL) 
- ##########################################################################
- # RHCS 9.5:
- ##########################################################################
- Bugzilla Bug #1633423 - Rebase redhat-pki, redhat-pki-theme, pki-core, and
  pki-console to 10.5.16 in RHCS 9.5
- Bugzilla Bug #1700921 - Update Red Hat logo in RHCS theme packages
  (Web UI + Console) [ascheel, mharmsen]

* Mon Mar 18 2019 Dogtag Team <pki-devel@redhat.com> 10.5.16-1
- ##########################################################################
- # RHEL 7.7:
- ##########################################################################
- Bugzilla Bug #1633422 - Rebase pki-core from 10.5.9 to 10.5.16 (RHEL) 
- ##########################################################################
- # RHCS 9.5:
- ##########################################################################
- Bugzilla Bug #1633423 - Rebase redhat-pki, redhat-pki-theme, pki-core, and
  pki-console to 10.5.16 in RHCS 9.5

* Fri Feb  1 2019 Dogtag Team <pki-devel@redhat.com> 10.5.9-3
- ##########################################################################
- # RHEL 7.6:
- ##########################################################################
- Bugzilla Bug #1557569 - Re-base pki-core from 10.5.1 to latest upstream
  10.5.x (RHEL) 
- ##########################################################################
- # RHCS 9.4:
- ##########################################################################
- Bugzilla Bug #1557570 - Re-base pki-core from 10.5.1 to latest upstream
  10.5.x (RHCS)
- Updated Batch Update Information to Version 3 (mharmsen)

* Mon Dec 17 2018 Dogtag Team <pki-devel@redhat.com> 10.5.9-2
- ##########################################################################
- # RHEL 7.6:
- ##########################################################################
- Bugzilla Bug #1557569 - Re-base pki-core from 10.5.1 to latest upstream
  10.5.x (RHEL) 
- Bugzilla Bug #1659939 - CC: Simplifying Web UI session timeout
  configuration [rhel-7.6.z] (edewata)
- ##########################################################################
- # RHCS 9.4:
- ##########################################################################
- Bugzilla Bug #1557570 - Re-base pki-core from 10.5.1 to latest upstream
  10.5.x (RHCS)
- Bugzilla Bug #1639836 - CC: Identify RHCS version of CA, KRA, OCSP, and
  TKS using browser [RHCS] (cfu, jmagne, mharmsen)
- Added Batch Update Information to Product Version (mharmsen)

* Tue Oct 16 2018 Dogtag Team <pki-devel@redhat.com> 10.5.9-1
- ##########################################################################
- # RHEL 7.6:
- ##########################################################################
- Bugzilla Bug #1557569 - Re-base pki-core from 10.5.1 to latest upstream
  10.5.x (RHEL) 
- ##########################################################################
- # RHCS 9.4:
- ##########################################################################
- Bugzilla Bug #1557570 - Re-base pki-core from 10.5.1 to latest upstream
  10.5.x (RHCS)
- Bugzilla Bug #1639836 - CC: Identify RHCS version of CA, KRA, OCSP, and
  TKS using browser [RHCS] (cfu, jmagne, mharmsen)

* Mon Nov 27 2017 Dogtag Team <pki-devel@redhat.com> 10.5.1-2
- ##########################################################################
- # RHEL 7.5:
- ##########################################################################
- Bugzilla Bug #1473452 - Rebase pki-core to latest upstream 10.5.x release
  (RHEL)
- ##########################################################################
- # RHCS 9.3:
- ##########################################################################
- Bugzilla Bug #1471303 - Rebase redhat-pki, redhat-pki-theme, pki-core, and
  pki-console to 10.5.x in RHCS 9.3

* Thu Nov  2 2017 Dogtag Team <pki-devel@redhat.com> 10.5.1-1
- ##########################################################################
- # RHEL 7.5:
- ##########################################################################
- Bugzilla Bug #1473452 - Rebase pki-core to latest upstream 10.5.x release
  (RHEL)
- ##########################################################################
- # RHCS 9.3:
- ##########################################################################
- Bugzilla Bug #1471303 - Rebase redhat-pki, redhat-pki-theme, pki-core, and
  pki-console to 10.5.x in RHCS 9.3

* Thu Oct 19 2017 Dogtag Team <pki-devel@redhat.com> 10.5.0-1
- ##########################################################################
- # RHEL 7.5:
- ##########################################################################
- Bugzilla Bug #1473452 - Rebase pki-core to latest upstream 10.5.x release
  (RHEL)
- ##########################################################################
- # RHCS 9.3:
- ##########################################################################
- Bugzilla Bug #1471303 - Rebase redhat-pki, redhat-pki-theme, pki-core, and
  pki-console to 10.5.x in RHCS 9.3

* Wed Jul 26 2017 Fedora Release Engineering <releng@fedoraproject.org> - 10.4.8-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Mon Jun 19 2017 Dogtag Team <pki-devel@redhat.com> 10.4.8-1
- Updated version number to 10.4.8-1

* Mon Jun  5 2017 Dogtag Team <pki-devel@redhat.com> 10.4.7-1
- Updated version number to 10.4.7-1

* Tue May 30 2017 Dogtag Team <pki-devel@redhat.com> 10.4.6-1
- Updated version number to 10.4.6-1

* Mon May 22 2017 Dogtag Team <pki-devel@redhat.com> 10.4.5-1
- Updated version number to 10.4.5-1

* Tue May  9 2017 Dogtag Team <pki-devel@redhat.com> 10.4.4-1
- Updated version number to 10.4.4-1

* Mon May  1 2017 Dogtag Team <pki-devel@redhat.com> 10.4.3-1
- Updated version number to 10.4.3-1

* Mon Apr 17 2017 Dogtag Team <pki-devel@redhat.com> 10.4.2-1
- Updated version number to 10.4.2-1

* Wed Mar 29 2017 Dogtag Team <pki-devel@redhat.com> 10.4.1-1
- Bugzilla Bug #1394309 - Rebase pki-core to 10.4.x in RHEL-7.4
- Bugzilla Bug #1394315 - Rebase redhat-pki, redhat-pki-theme, pki-core, and
  pki-console to 10.4.x

* Tue Mar 14 2017 Dogtag Team <pki-devel@redhat.com> 10.4.0-1
- Bugzilla Bug #1394309 - Rebase pki-core to 10.4.x in RHEL-7.4
- Bugzilla Bug #1394315 - Rebase redhat-pki, redhat-pki-theme, pki-core, and
  pki-console to 10.4.x

* Mon Jun 20 2016 Dogtag Team <pki-devel@redhat.com> 10.3.3-1
- Updated release number to 10.3.3

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-2
- Updated 'java', 'java-headless', and 'java-devel' dependencies to 1:1.8.0.

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-1
- Updated version number to 10.3.2

* Wed May 18 2016 Dogtag Team <pki-devel@redhat.com> 10.3.1-2
- PKI TRAC Ticket #2287 - Adding token UNFORMATTED state [edewata]

* Tue May 17 2016 Dogtag Team <pki-devel@redhat.com> 10.3.1-1
- Update version number to 10.3.1

* Sat Jul 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-1
- Update version number to 10.2.6

* Sat Jun 20 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-2
- Remove ExcludeArch directive

* Fri Jun 19 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-1
- Update version number to 10.2.5

* Tue May 26 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-1
- Updated version number to 10.2.4

* Fri Apr 24 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-1
- Initial release
