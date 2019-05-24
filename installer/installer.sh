#!/bin/bash
echo "=> Installation started!"
unzip -o installer.zip
echo "=> Unzipped installer.zip"
chmod 777 /usr/local/sf/lib/perl/5.10.1/SF/SFDataCorrelator/HostInput.pm
echo "=> Changed HostInput rights"
chmod -R 777 /usr/lib/perl5/site_perl/5.10.1
echo "=> Changed Perl rights"
cp -f  /usr/local/sf/lib/perl/5.10.1/SF/SFDataCorrelator/HostInput.pm /usr/local/sf/lib/perl/5.10.1/SF/SFDataCorrelator/HostInput.pm_backup
echo "=> Backed up HostInput.pm to HostInput.pm_backup"
cp -f  /Volume/home/admin/HostInput.pm /usr/local/sf/lib/perl/5.10.1/SF/SFDataCorrelator/HostInput.pm
echo "=> Copied new HostInput.pm and replaced"
unzip -o perl-modules.zip -d /
echo "=> Unzipped Perl Modules"
chmod -R 444 /usr/local/sf/lib/perl/5.10.1/SF/SFDataCorrelator/HostInput.pm
chmod -R 755 /usr/lib/perl5/site_perl/5.10.1
echo "=> Restoring access rights"
chmod +x importer.sh
mkdir export
chown admin.admin ./export
chmod 777 ./export
echo "=> Cleaning up installer files"
shopt -s extglob
rm -v !("export"|"importer.sh")
shopt -u extglob
echo "=> Installation finished!"