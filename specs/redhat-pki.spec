%if 0%{?fedora} || 0%{?rhel} > 7
%global with_python3 1
%else
%global with_python3 0
%endif

# Optionally fetch the release from the environment variable 'PKI_RELEASE'
%define use_pki_release %{getenv:USE_PKI_RELEASE}
%if 0%{?use_pki_release}
%define pki_release %{getenv:PKI_RELEASE}
%endif

Summary:          Red Hat Public Key Infrastructure (PKI) Suite
Name:             redhat-pki
%if 0%{?rhel}
Version:                10.5.18
%define redhat_release  1
%define redhat_stage    0
%define default_release %{redhat_release}.%{redhat_stage}
#%define default_release %{redhat_release}
%else
Version:                10.5.18
%define fedora_release  1
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

# The entire source code is GPLv2 except for 'pki-tps' which is LGPLv2
License:          GPLv2 and LGPLv2
URL:              http://pki.fedoraproject.org/
Group:            System Environment/Daemons
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:        noarch

%define redhat_pki_theme_version   %{version}
%if 0%{?fedora} >= 27 || 0%{?rhel} > 7
%define esc_version                1.1.1
%else
%define esc_version                1.1.0
%endif
# NOTE:  The following package versions are TLS compliant:
%if 0%{?rhel}
%define pki_core_rhel_version      10.5.18
%define pki_core_rhcs_version      %{version}
%else
%define pki_core_version           %{version}
%endif
%define pki_console_version        %{version}

%if 0%{?fedora} >= 27 || 0%{?rhel} > 7
# Exclude 'aarch64' and 's390x' architectures since
# 'esc' does not exist on these two platforms
ExcludeArch: aarch64 s390x
%endif

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Red Hat PKI theme packages
Requires:         redhat-pki-server-theme >= %{redhat_pki_theme_version}
Requires:         redhat-pki-console-theme >= %{redhat_pki_theme_version}

%if 0%{?rhel}
# Make certain that this 'meta' package requires the latest version(s)
# of ALL Red Hat PKI core (RHEL) packages
Requires:         pki-base >= %{pki_core_rhel_version}
Requires:         pki-base-java >= %{pki_core_rhel_version}
%if 0%{?with_python3}
Requires:         pki-base-python3 >= %{pki_core_rhel_version}
%endif
Requires:         pki-ca >= %{pki_core_rhel_version}
Requires:         pki-kra >= %{pki_core_rhel_version}
Requires:         pki-server >= %{pki_core_rhel_version}
Requires:         pki-symkey >= %{pki_core_rhel_version}
Requires:         pki-tools >= %{pki_core_rhel_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Red Hat PKI core (RHCS) packages
Requires:         pki-ocsp >= %{pki_core_rhcs_version}
Requires:         pki-tks >= %{pki_core_rhcs_version}
Requires:         pki-tps >= %{pki_core_rhcs_version}
%else
# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI core packages
Requires:         pki-base >= %{pki_core_version}
Requires:         pki-base-java >= %{pki_core_version}
%if 0%{?with_python3}
Requires:         pki-base-python3 >= %{pki_core_version}
%endif
Requires:         pki-ca >= %{pki_core_version}
Requires:         pki-kra >= %{pki_core_version}
Requires:         pki-ocsp >= %{pki_core_version}
Requires:         pki-server >= %{pki_core_version}
Requires:         pki-symkey >= %{pki_core_version}
Requires:         pki-tks >= %{pki_core_version}
Requires:         pki-tools >= %{pki_core_version}
Requires:         pki-tps >= %{pki_core_version}
%endif

# Make certain that this 'meta' package requires the latest version(s)
# of Red Hat PKI console
Requires:         pki-console >= %{pki_console_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Red Hat PKI clients
Requires:         esc >= %{esc_version}

%description
The Red Hat Public Key Infrastructure (PKI) Suite is comprised of the following
five subsystems and a client (for use by a Token Management System):

  * Certificate Authority (CA)
  * Key Recovery Authority (KRA)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing System (TPS)
  * Enterprise Security Client (ESC)

Additionally, it provides a console GUI application used for server and
user/group administration of CA, KRA, OCSP, and TKS, as well as various
command-line tools used to assist with a PKI deployment.

To successfully deploy instances of a CA, KRA, OCSP, TKS, or TPS,
a Tomcat Web Server must be up and running locally on this machine.

To meet the database storage requirements of each CA, KRA, OCSP, TKS, or TPS
instance, a 389 Directory Server must be up and running either locally on
this machine, or remotely over the attached network connection.

Finally, although they are no longer supplied by this 'meta' package,
javadocs are available for both JSS (jss-javadoc) and portions of
the Red Hat PKI API (pki-javadoc).

NOTE:  As a convenience for standalone deployments, this 'redhat-pki'
       top-level meta package supplies Red Hat themes for use by the
       certificate server packages:

         * redhat-pki-theme (Red Hat Certificate System deployments)
           * redhat-pki-server-theme
           * redhat-pki-console-theme

%prep
cat > README <<EOF
This package is just a "meta-package" whose dependencies pull in all of the
packages comprising the Red Hat Public Key Infrastructure (PKI) Suite.
EOF

%files
%defattr(-,root,root,-)
%doc README

%changelog
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

* Thu Aug 24 2017 Dogtag Team <pki-devel@redhat.com> 10.4.8-3
- Added ExcludeArch directives for 'aarch64' and 's390x' on Fedora 27+ due
  to dependency on 'esc' which does not exist on these two platforms

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
- Updated version number to 10.3.3

* Tue Jun 14 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-2
- Provided cleaner runtime dependency separation

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-1
- Updated version number to 10.3.2

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
