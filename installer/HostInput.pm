package SF::SFDataCorrelator::HostInput;

use URI::Encode qw(uri_encode uri_decode);
use Encode qw(decode encode);
use Text::CSV::Encoded;
use FlyLoader;
use Socket;
use Data::Dumper;
use Error qw(:try);
use strict;
use warnings;
use Storable qw(dclone);
use Text::CSV;
use File::Slurp;
#use encoding 'utf8';
use utf8;

my $result_string;
my $do_sync = 1;

my ($source_type_user,
    $source_type_scan,
    $source_type_app) = (getPkgVar( "SF::SFDataCorrelator::UserMessage", '$SOURCE_TYPE_USER'),
                         getPkgVar( "SF::SFDataCorrelator::UserMessage", '$SOURCE_TYPE_SCAN'),
                         getPkgVar( "SF::SFDataCorrelator::UserMessage", '$SOURCE_TYPE_APP'));

our $DEFAULT_LOCATION = "/etc/sf/keys/hostinput_clients";
our $DEFAULT_LOCATION_RELOC = SF::Reloc::RelocateFilename($DEFAULT_LOCATION);

my ($update_flag,
    $delete_flag,
    $delete_all_vuln_flag,
    $delete_all_generic_flag,
    $delete_all_flag) = (getPkgVar("SF::SFDataCorrelator::UserMessage",'$UPDATE_SCAN_RESULT'),
                         getPkgVar("SF::SFDataCorrelator::UserMessage",'$DELETE_SCAN_RESULT'),
                         getPkgVar("SF::SFDataCorrelator::UserMessage",'$DELETE_ALL_VULN_SCAN_RESULT'),
                         getPkgVar("SF::SFDataCorrelator::UserMessage",'$DELETE_ALL_GENERIC_SCAN_RESULT'),
                         getPkgVar("SF::SFDataCorrelator::UserMessage",'$DELETE_ALL_SCAN_RESULT'));

#
# Field list for importing CSV files
#
our $host_input_fields =
{
    'AddHost'               => [ 'ip_address', 'mac_address' ],
    'DeleteHost'            => [ 'ip_address', 'mac_address' ],

    'SetValidVuln'          => [ 'ip_address', 'port', 'proto', 'type', 'vuln_id' ],
    'SetInvalidVuln'        => [ 'ip_address', 'port', 'proto', 'type', 'vuln_id' ],

    'AddProtocol'           => [ 'ip_address', 'mac_address', 'proto', 'type' ],
    'DeleteProtocol'        => [ 'ip_address', 'mac_address', 'proto', 'type' ],

    'AddHostAttribute'      => [ 'attribute_name', 'attribute_type' ],
    'DeleteHostAttribute'   => [ 'attribute_name' ],
    'SetAttributeValue'     => [ 'ip_address', 'attribute', 'value' ],
    'DeleteAttributeValue'  => [ 'ip_address', 'attribute' ],

    'AddClientApp'          => [ 'ip_address', 'app_name', 'app_type', 'version' ],
    'DeleteClientApp'       => [ 'ip_address', 'app_name', 'app_type', 'version' ],
    'DeleteClientAppPayload'=> [ 'ip_address', 'app_name', 'app_type', 'version', 'payload_type', 'payload_id' ],

    'DeleteService'         => [ 'ip_address', 'port', 'proto' ],

    'AddService'            => [ 'ip_address', 'port', 'proto', 'service', 'vendor_str', 'version_str', 'vendor_id', 'product_id', 'major', 'minor', 'revision', 'build', 'patch', 'extension' ],
    'SetService'            => [ 'ip_address', 'port', 'proto', 'service', 'vendor_str', 'version_str', 'vendor_id', 'product_id', 'major', 'minor', 'revision', 'build', 'patch', 'extension' ],

    'UnsetService'          => [ 'ip_address', 'port', 'proto' ],

    'SetOS'                 => [ 'ip_address', 'vendor_str', 'product_str', 'version_str', 'vendor_id', 'product_id', 'major', 'minor', 'revision', 'build', 'patch', 'extension', 'device_string', 'mobile', 'jailbroken' ],
    'UnsetOS'               => [ 'ip_address' ],

    'AddFix'                => [ 'ip_address', 'port', 'proto', 'fix_id' ],
    'RemoveFix'             => [ 'ip_address', 'port', 'proto', 'fix_id' ],

    'SetMap'                => [ 'map_name' ],
    'SetSourceType'         => [ 'source_type_name' ],
    'SetSource'             => [ 'source_name', 'option' ],
    'SetDomain'             => [ 'domain' ],

    'AddScanResult'         => [ 'ip_address', 'scanner_id', 'vuln_id', 'port', 'proto', 'name', 'desc', 'cve_id_list', 'bugtraq_id_list' ],

    'DeleteScanResult'      => [ 'ip_address', 'scanner_id', 'id_list', 'port', 'proto' ],

    'ScanUpdate'            => [],
    'ScanFlush'             => [],

};

# Create a local hash for maps for this instance of perl (so we don't have to keep loading from the EO Store)
our $map_hash;

our $__current_map;
our $__current_source_id;

my $app_ids;
my $app_names;
my $source_types;
my $source_type_names;
my $scan_type_ids;
my $Sock_AddScanResult; # Hashref with key: $sock, value: $AddScanResult_Cmds
my $Sock_DelScanResult; # Hashref with key: $sock, value: $DelScanResult_Cmds
my $postprocessing_netmap_num;

#
# Resets module scoped variables and memoize caches. Called by persistent perl
# server between each handled request.
#
# Please add any new module scoped variables that need to be reset to their
# defaults between each request.
#
sub reset_module
{
    undef $result_string;
    undef $map_hash;
    undef $__current_map;
    undef $__current_source_id;
    undef $app_ids;
    undef $app_names;
    undef $source_types;
    undef $source_type_names;
    undef $scan_type_ids;
    undef $Sock_AddScanResult;
    undef $Sock_DelScanResult;
    undef $postprocessing_netmap_num;
    $do_sync = 1;
}

sub SetDoSync
{
    my ($val) = @_;

    $do_sync = $val;
}

sub ImportCSV
{
    my ($filename, $test) = @_;

    if(!open(FILE,"<:encoding(utf8)",$filename))
    {
        warn "Error opening: " . $filename . " file.";
        return undef;
    }

    my $buffer = read_file($filename);

    close FILE;

    importCSVBuffer($buffer, undef, undef, $test);

    return 0;
}

sub importCSVBuffer
{
    my ($buffer, $sock, $domain_uuid, $test) = @_;
    my ($buf, @buffer_array);

    if (SF::COOP::enabled() && !$test)
    {
        # Max size limit for the 'options' column of HA_transaction table is 64kb
        # Split the buffer if its size is greater than 63kb
        if (length($buffer) > 64512)
        {
            @buffer_array = SplitBuffer($buffer);
        }
        elsif (length($buffer) > 0)
        {
            push(@buffer_array, $buffer);
        }

        foreach $buf (@buffer_array)
        {
            SF::COOP::add_ha_transaction(\&ProcessCSVBuffer, { args => [$buf, $test, undef, $domain_uuid] }, "Process HostInput Commands", 10);
        }
    }

    ProcessCSVBuffer($buffer, $test, $sock, $domain_uuid);
}

sub SplitBuffer
{
    my ($text) = @_;
    my $buffer_size = 64512; #63kb
    my $buffer = "";
    my $headers = "";
    my ($line, @buffer_array);

    my @lines = split('\n', $text);

    foreach $line (@lines)
    {
        if (length($buffer) + length($line) > $buffer_size)
        {
            push(@buffer_array, $buffer);
            $buffer = $headers;
        }

        $buffer .= $line."\n";

        #Extract SetMap, SetSource, SetSourceType and SetDomain commands to include in every buffer
        if ($line =~ /^Set(Map|Source|SourceType|Domain)/)
        {
           $headers .= $line."\n";
        }
    }

    if ($buffer ne "")
    {
        push(@buffer_array, $buffer);
    }

    return @buffer_array;
}

# For HA, the entire buffer will be sent to the peer as a single HA transaction.
# Therefore, we must disable HA transactions for the individual actions.
# Assuming only single-threaded applications call this function, we set the global variable 'do_sync'.
# For user operations via the UI, we need to HA-sync the individual actions,
# but that happens in a separate process where HA-sync is always enabled for the individual actions.
sub ProcessCSVBuffer
{
    my ($buffer, $test, $sock, $domain_uuid) = @_;

    SetDoSync(0);

    my $cmds = parseCSVBuffer($buffer);

    HandleCmds($cmds, $test, $sock, $domain_uuid);

    if (!$test)
    {
        PostProcessingCmds($cmds, $sock);
    }

    SetDoSync(1);
}

sub getResultString
{
    return $result_string;
}

sub parseCSVBuffer
{
    my ($text) = @_;

    my (@cmds, $line);

    my @lines = split('\n', $text);

    foreach $line (@lines)
    {
        procLine($line,\@cmds);
    }

    return \@cmds;
}

sub procLine
{
    my ($line,$cmds) = @_;

    chomp $line;
    #$line = encode('utf8',$line);
    #print "DBG ASHES: $line\r\n";
    return if ($line =~ /^\s*#|^\s$/);
    return if ($line eq "");

    my ($csv,@columns,$list);
    $csv = Text::CSV::Encoded->new(
                          { allow_whitespace => 1,
                          }
                         );   # create a new CSV object
    #ASHES
    #$csv->encoding_in('utf8')->encoding_out('utf8');
    if( $csv->parse($line) )
    {
        @columns = $csv->fields;
    }
    else
    {
        my $err = $csv->error_input;
        AddLog("Text::CSV::parse() failed on line: $line, argument: $err");
    }
    $list = \@columns;

    my $custom_map_name;
    if (@$list[0] =~ /^SetMap:(.*$)/)
    {
        #warn "SetMap name to $1";
        $custom_map_name = $1;
        splice(@$list, 0, 1);
    }

    my $field_list = $host_input_fields->{@$list[0]};

    if (defined($field_list))
    {
        my $count = 1;
        my $hsh;

        if ($custom_map_name)
        {
            $hsh->{custom_map_name} = $custom_map_name;
        }

        foreach my $field (@$field_list)
        {
            $hsh->{$field} = uri_decode(@$list[$count]);
            #print "DBG ASHES @$list[$count]";
            $count++;
        }

        # get rest of stuff in $rest_of_list now
        my @rest_in_list;
        for( my $iter = $count; $iter<@$list; $iter++ )
        {
            push @rest_in_list,@$list[$iter];
        }

        if (defined($hsh))
        {
            push @$cmds, { cmd => @$list[0], params => $hsh, list => \@rest_in_list };
        }
        else
        {
            push @$cmds, { cmd => @$list[0] }; # if this is the command without parameters
        }
    }
    else
    {
        AddLog("WARN: ignoring unknown key '". @$list[0] . "'. Line: $line");
    }
}

sub HandleCmds
{
    my ($cmds,$test,$sock, $cert_domain_uuid) = @_;

    $result_string = "";
    my $str;
    my $source_type_id = $source_type_app;
    my $num_cmds = 0;

    if (!defined($cert_domain_uuid))
    {
        $cert_domain_uuid = SF::MultiTenancy::getGlobalDomainId();
    }
    my $domain_uuid = $cert_domain_uuid;
    SF::MultiTenancy::switchDomain($domain_uuid);

    foreach my $hsh (@$cmds)
    {
        my $rval = 0;
        if ($test)
        {
            print "command: " . $hsh->{cmd} . "\n";
            print "params: " . Dumper($hsh->{params});

            # Need to verify Map name if it is set
        }
        else
        {
            my $original_map = $SF::SFDataCorrelator::HostInput::__current_map;
            if ($hsh->{cmd} eq 'SetSource')
            {
                if (!(SF::MultiTenancy::isLeafDomain($domain_uuid)))
                {
                    $str = "[$hsh->{cmd}]: " . SF::MultiTenancy::getCurrentDomainName() . " is not a leaf domain\n";
                    AddLog($str);
                    return;
                }
                SetCurrentSource($source_type_id,$hsh->{params}{source_name},
                                 $hsh->{params}{option});
                #$result_string .= $str.'Successfully Executed Command: '.$hsh->{cmd}."\n";
                next;
            }
            if ($hsh->{cmd} eq 'SetSourceType')
            {
                $source_type_id = GetSourceTypeIDByName($hsh->{params}{source_type_name});
                next;
            }
            if ($hsh->{cmd} eq 'SetDomain')
            {
                my $domain = $hsh->{params}{domain};
                if (SF::Types::is_valid("uuid", $domain, {'ignore_dashes' => 1}))
                {
                    $domain_uuid = $domain;
                }
                else
                {
                    my @args = split(/\s*\\\s*/, $domain);
                    if (@args >= 2)
                    {
                        shift @args if ($args[0] eq "Global");
                    }
                    try {
                        $domain_uuid = SF::MultiTenancy::getDomainUUIDByName(@args);
                    } catch Error with {
                        $domain_uuid = undef;
                        if (!defined($sock))
                        {
                            $str = "[$hsh->{cmd}]: Unknown domain: $domain\n";
                        }
                        else
                        {
                            # Unknown domain but use the unauthorized message to avoid information leak.
                            $str = "[$hsh->{cmd}]: Domain $domain is not in the certificate domain\n";
                        }
                        AddLog($str);
                    };
                }
                return unless $domain_uuid;
                if (($cert_domain_uuid ne $domain_uuid) && ($cert_domain_uuid ne SF::MultiTenancy::getGlobalDomainId()))
                {
                    if (!(SF::MultiTenancy::isAncestorDomain($cert_domain_uuid, $domain_uuid)))
                    {
                        $str = "[$hsh->{cmd}]: Domain $domain is not in the certificate domain\n";
                        AddLog($str);
                        return;
                    }
                }

                try {
                    SF::MultiTenancy::switchDomain($domain_uuid);
                } catch Error with {
                    $domain_uuid = undef;
                    $str = "[$hsh->{cmd}]: Invalid domain uuid\n";
                    AddLog($str);
                };
                return unless $domain_uuid;

                next;
            }
            if ( $hsh->{cmd} ne 'AddScanResult' &&
                 $hsh->{cmd} ne 'DeleteScanResult' &&
                 $hsh->{cmd} ne 'ScanUpdate' &&
                 $hsh->{cmd} ne 'ScanFlush' && !SourceSet())
            {
                $str = "[$hsh->{cmd}]: Must set source application\n";
                print $str;
                if(defined($sock))
                {
                    $result_string .= $str;
                }
                else
                {
                    return;
                }
            }

            my $source_id = GetCurrentSource();

            $num_cmds++;

            if (defined($hsh->{params}{custom_map_name}))
            {
                my $custom_map_name = $hsh->{params}{custom_map_name};
                $str = " (map using '$custom_map_name')\n";
                return if( SetCurrent3rdPartyMap($custom_map_name, $domain_uuid) == -1 );
                $result_string .= $str;
            }

            if ($hsh->{cmd} eq 'AddHost')
            {
                $rval = SF::SFDataCorrelator::HostInput::AddHost($source_type_id, $source_id, $hsh->{params}{ip_address}, $hsh->{params}{mac_address} );
            }
            elsif ($hsh->{cmd} eq 'DeleteHost')
            {
                $rval = SF::SFDataCorrelator::HostInput::DeleteHost($source_type_id, $source_id, $hsh->{params}{ip_address}, [$hsh->{params}{mac_address}] );
            }
            elsif ($hsh->{cmd} eq 'SetValidVuln')
            {
                my $vuln;
                $vuln->{port} = $hsh->{params}{port};
                $vuln->{proto} = $hsh->{params}{proto};
                $vuln->{vuln_id} = $hsh->{params}{vuln_id};
                $rval = SF::SFDataCorrelator::HostInput::SetValidVulns($source_type_id, $source_id, $hsh->{params}{ip_address},
                                                                    [ $vuln ], $hsh->{params}{type});
            }
            elsif ($hsh->{cmd} eq 'SetInvalidVuln')
            {
                my $vuln;
                $vuln->{port} = $hsh->{params}{port};
                $vuln->{proto} = $hsh->{params}{proto};
                $vuln->{vuln_id} = $hsh->{params}{vuln_id};
                $rval = SF::SFDataCorrelator::HostInput::SetInvalidVulns($source_type_id, $source_id, $hsh->{params}{ip_address},
                                                                        [ $vuln ], $hsh->{params}{type});
            }
            elsif ($hsh->{cmd} eq 'AddProtocol')
            {
                $rval = SF::SFDataCorrelator::HostInput::AddProtocol($source_type_id, $source_id, $hsh->{params}{ip_address}, [$hsh->{params}{mac_address}],
                                                                    $hsh->{params}{proto}, $hsh->{params}{type});
            }
            elsif ($hsh->{cmd} eq 'DeleteProtocol')
            {
                $rval = SF::SFDataCorrelator::HostInput::DeleteProtocol($source_type_id, $source_id, $hsh->{params}{ip_address}, [$hsh->{params}{mac_address}],
                                                                        $hsh->{params}{proto}, $hsh->{params}{type});
            }
            elsif ($hsh->{cmd} eq 'AddHostAttribute')
            {
                $rval = SF::SFDataCorrelator::HostInput::AddHostAttribute($source_type_id, $source_id, $hsh->{params}{attribute_name}, $hsh->{params}{attribute_type});
            }
            elsif ($hsh->{cmd} eq 'DeleteHostAttribute')
            {
                $rval = SF::SFDataCorrelator::HostInput::DeleteHostAttribute($source_type_id, $source_id, $hsh->{params}{attribute_name});
            }
            elsif ($hsh->{cmd} eq 'SetAttributeValue')
            {
                $rval = SF::SFDataCorrelator::HostInput::SetAttributeValue($source_type_id, $source_id, $hsh->{params}{ip_address},
                                                                        $hsh->{params}{attribute}, $hsh->{params}{value});
            }
            elsif ($hsh->{cmd} eq 'DeleteAttributeValue')
            {
                $rval = SF::SFDataCorrelator::HostInput::DeleteAttributeValue($source_type_id, $source_id, $hsh->{params}{ip_address},
                                                                            $hsh->{params}{attribute});
            }
            elsif ($hsh->{cmd} eq 'AddClientApp')
            {
                $rval = SF::SFDataCorrelator::HostInput::AddClientApp($source_type_id, $source_id, $hsh->{params}{ip_address},
                                                                    $hsh->{params}{app_name}, $hsh->{params}{app_type}, $hsh->{params}{version});
            }
            elsif ($hsh->{cmd} eq 'DeleteClientApp')
            {
                $rval = SF::SFDataCorrelator::HostInput::DeleteClientApp($source_type_id, $source_id, $hsh->{params}{ip_address},
                                                                        $hsh->{params}{app_name}, $hsh->{params}{app_type}, $hsh->{params}{version});
            }
            elsif ($hsh->{cmd} eq 'DeleteClientAppPayload')
            {
                $rval = SF::SFDataCorrelator::HostInput::DeleteClientAppPayload($source_type_id, $source_id, $hsh->{params}{ip_address},
                                                                        $hsh->{params}{app_name}, $hsh->{params}{app_type}, $hsh->{params}{version}, $hsh->{params}{payload_type}, $hsh->{params}{payload_id});
            }
            elsif ($hsh->{cmd} eq 'DeleteService')
            {
                $rval = SF::SFDataCorrelator::HostInput::DeleteService($source_type_id, $source_id, $hsh->{params}{ip_address},
                                                                        $hsh->{params}{port}, $hsh->{params}{proto});
            }
            elsif ($hsh->{cmd} eq 'AddService')
            {
                my $service;
                $service->{port} = $hsh->{params}{port};
                $service->{proto} = $hsh->{params}{proto};
                $service->{service_name} = $hsh->{params}{service};
                $service->{vendor_str} = $hsh->{params}{vendor_str};
                $service->{version_str} = $hsh->{params}{version_str};
                $service->{vendor_id} = $hsh->{params}{vendor_id};
                $service->{product_id} = $hsh->{params}{product_id};
                $service->{major} = $hsh->{params}{major};
                $service->{minor} = $hsh->{params}{minor};
                $service->{revision} = $hsh->{params}{revision};
                $service->{build} = $hsh->{params}{build};
                $service->{patch} = $hsh->{params}{patch};
                $service->{extension} = $hsh->{params}{extension};

                $rval = SF::SFDataCorrelator::HostInput::AddService($source_type_id, $source_id, $hsh->{params}{ip_address}, $service);
            }
            elsif ($hsh->{cmd} eq 'SetService')
            {
                my $service;
                $service->{port} = $hsh->{params}{port};
                $service->{proto} = $hsh->{params}{proto};
                $service->{service_name} = $hsh->{params}{service};
                $service->{vendor_str} = $hsh->{params}{vendor_str};
                $service->{version_str} = $hsh->{params}{version_str};
                $service->{vendor_id} = $hsh->{params}{vendor_id};
                $service->{product_id} = $hsh->{params}{product_id};
                $service->{major} = $hsh->{params}{major};
                $service->{minor} = $hsh->{params}{minor};
                $service->{revision} = $hsh->{params}{revision};
                $service->{build} = $hsh->{params}{build};
                $service->{patch} = $hsh->{params}{patch};
                $service->{extension} = $hsh->{params}{extension};

                $rval = SF::SFDataCorrelator::HostInput::SetService($source_type_id, $source_id, $hsh->{params}{ip_address}, $service);
            }
            elsif ($hsh->{cmd} eq 'UnsetService')
            {
                my $service;
                $service->{drop_user_product} = 1;
                $service->{port} = $hsh->{params}{port};
                $service->{proto} = $hsh->{params}{proto};
                $rval = SF::SFDataCorrelator::HostInput::SetService($source_type_id, $source_id, $hsh->{params}{ip_address}, $service);
            }
            elsif ($hsh->{cmd} eq 'SetOS')
            {
                my $os;
                $os->{port} = $hsh->{params}{port};
                $os->{proto} = $hsh->{params}{proto};
                $os->{service_name} = $hsh->{params}{service};
                $os->{vendor_str} = $hsh->{params}{vendor_str};
                $os->{product_str} = $hsh->{params}{product_str};
                $os->{version_str} = $hsh->{params}{version_str};
                $os->{vendor_id} = $hsh->{params}{vendor_id};
                $os->{product_id} = $hsh->{params}{product_id};
                $os->{major} = $hsh->{params}{major};
                $os->{minor} = $hsh->{params}{minor};
                $os->{revision} = $hsh->{params}{revision};
                $os->{build} = $hsh->{params}{build};
                $os->{patch} = $hsh->{params}{patch};
                $os->{extension} = $hsh->{params}{extension};
                $os->{device_string} = $hsh->{params}{device_string};
                $os->{mobile} = $hsh->{params}{mobile};
                $os->{jailbroken} = $hsh->{params}{jailbroken};

                $rval = SF::SFDataCorrelator::HostInput::SetOS($source_type_id, $source_id, $hsh->{params}{ip_address}, $os);
            }
            elsif ($hsh->{cmd} eq 'AddFix')
            {
                $rval = AddFix($source_type_id, $source_id, $hsh->{params}{ip_address}, $hsh->{params}{port}, $hsh->{params}{proto}, $hsh->{params}{fix_id});
            }
            elsif ($hsh->{cmd} eq 'RemoveFix')
            {
                $rval = RemoveFix($source_type_id, $source_id, $hsh->{params}{ip_address}, $hsh->{params}{port}, $hsh->{params}{proto}, $hsh->{params}{fix_id});
            }
            elsif ($hsh->{cmd} eq 'UnsetOS')
            {
                my $os = { drop_user_product => 1 };
                $rval = SF::SFDataCorrelator::HostInput::SetOS($source_type_id, $source_id, $hsh->{params}{ip_address}, $os);
            }
            elsif ($hsh->{cmd} eq 'SetMap')
            {
                return if( SetCurrent3rdPartyMap($hsh->{params}{map_name}, $domain_uuid) == -1 );
                $original_map = $SF::SFDataCorrelator::HostInput::__current_map;
                if($original_map->{name})
                {
                    print "Current Map Set to $original_map->{name}\n";
                }
                else
                {
                    return;
                }
            }
            elsif ($hsh->{cmd} eq 'AddScanResult')
            {
                $rval = HandleCSVCmd_AddScanResult($hsh);
            }
            elsif ($hsh->{cmd} eq 'DeleteScanResult')
            {
                $rval = HandleCSVCmd_DeleteScanResult($hsh);
            }
            elsif ($hsh->{cmd} eq 'ScanFlush' ||
                   $hsh->{cmd} eq 'ScanUpdate')
            {
                $rval = 0;
            }
            else
            {
                AddLog("Unknown command ".$hsh->{cmd});
            }

            $SF::SFDataCorrelator::HostInput::__current_map = $original_map;
        }
        if( $rval == 0 )
        {
            my $action = 'Executed';
            $action = 'Queued' if($hsh->{cmd} eq 'AddScanResult');
        }
        else
        {
            $result_string .= 'Failed to Execute Command: '.getCmdInfo($hsh)."\n";
        }
    }
    $postprocessing_netmap_num = SF::MultiTenancy::getNetmapNum($domain_uuid);
    $result_string .= "Done processing $num_cmds commands.\n";
    print $result_string;
    # Clear the cached results and unswitch domains
    SF::MultiTenancy::reset_module();
}

sub getCmdInfo
{
    my ($hsh) = @_;

    my ($params,$str);

    $params = $hsh->{params};
    if( defined($params) )
    {
        #print Dumper($params);
        $str .= " Command: ".$hsh->{cmd};
        foreach my $item (@{$host_input_fields->{$hsh->{cmd}}})
        {
            $str .= " $item: ".$params->{$item} if(defined($params->{$item}));
        }
    }
    return $str;
}

sub strToRangeList
{
    my ($block) = @_;

    return if (!defined($block));
    my @list = split ',',$block;
    my @ranges;

    for my $item (@list)
    {
        my $low;
        my $high;
        my $exclude = 0;

        # Strip any whitespace
        $item =~ s/\s//g;

        if ($item =~ s/^!//)
        {
            $exclude = 1;
        }

        if ($item =~ /\//)
        {
            my ($addr, $cidr) = split "/",$item, 2;

            my $ipaddr;

            if (SF::Types::is_valid('ip',$item, {cidr => 1, ipv4 => 1}))
            {
                $ipaddr = NetAddr::IP->new("::ffff:$addr", $cidr+96);
            }
            elsif (SF::Types::is_valid('ip',$item, {cidr => 1, ipv6 => 1}))
            {
                $ipaddr = NetAddr::IP->new($addr, $cidr);
            }
            else
            {
                AddLog("'$item' is not a valid address");
            }

            if($ipaddr)
            {
                # need to re-create the objects so that the mask is set back to /128
                # Can interfere with network set reduction otherwise.
                my $low = NetAddr::IP->new($ipaddr->network()->addr());
                my $high = NetAddr::IP->new($ipaddr->broadcast()->addr());

                push @ranges, [ $low, $high, $exclude];
            }
        }
        elsif ($item =~ /-/)
        {
            my ($low, $high) = split "-",$item, 2;
            my ($ilow, $ihigh);

            if (SF::Types::is_valid('ip', $low, {ipv4 => 1}) && SF::Types::is_valid('ip', $high, {ipv4 => 1}))
            {
                $ilow = NetAddr::IP->new6("::ffff:$low");
                $ihigh = NetAddr::IP->new6("::ffff:$high");
            }
            elsif (SF::Types::is_valid('ip', $low, {ipv6 => 1}) && SF::Types::is_valid('ip', $high, {ipv6 => 1}))
            {
                $ilow = NetAddr::IP->new6($low);
                $ihigh = NetAddr::IP->new6($high);
            }
            else
            {
                AddLog("'$item' is not a valid address range");
            }

            if($ilow)
            {
                if ($ihigh >= $ilow)
                {
                    push @ranges, [ $ilow, $ihigh, $exclude];
                }
                else
                {
                    push @ranges, [ $ihigh, $ilow, $exclude];
                }
            }
        }
        else
        {
            my $addr = packIP($item);
            if($addr)
            {
                push @ranges, [$addr,$addr,$exclude];
            }
        }
    }

    return \@ranges;
}

#
# Function takes an address string (a comma delimited list of ranges, subnets, single addresses, exclusions) and
# builds an array of address ranges. This array will be used for specifying addresses for a HostInput message.
#
sub convertAddress
{
    my ($addr_string, $existing_ranges) = @_;

    my $ranges = strToRangeList($addr_string);
    my $new_set = SF::RNA::Util::reduceNetworkSet($ranges, $existing_ranges);

    return $new_set;
}

sub convertAddressOrUUID
{
    my ($addr_string) = @_;
    my $has_host_id = 0;

    return if (!defined($addr_string));

    my $addr_string_copy = $addr_string;

    $addr_string_copy =~ s/,.*$//g;
    if (SF::Types::is_valid("uuid", $addr_string_copy, {'ignore_dashes' => 1}))
    {
        $has_host_id = 1;
        my @list = split ',',$addr_string;
        my @ranges;
        my @ip_string_list;
        for my $item (@list)
        {
            # Strip any whitespace
            $item =~ s/\s//g;
            push @ranges, [$item, 0];
            if (SF::COOP::enabled())
            {
                my $host_ip = SF::RNA::Hosts::getHostIPs($item);
                push @ip_string_list, $host_ip->[0];
            }
        }
        my $ip_str = join(',', @ip_string_list);
        my $ip_list = convertAddress($ip_str) if defined($ip_str);
        return \@ranges, $has_host_id, $ip_list;
    }
    return convertAddress($addr_string), $has_host_id, undef;
}

sub packIP
{
    my ($addr_string) = @_;
    if (SF::Types::is_valid('ip', $addr_string, {ipv4 => 1}))
    {
        return NetAddr::IP->new6("::ffff:$addr_string");
    }
    elsif (SF::Types::is_valid('ip', $addr_string, {ipv6 => 1}))
    {
        return NetAddr::IP->new6($addr_string);
    }
    AddLog("'$addr_string' is not a valid address");
    return undef;
}

sub getCurrentLeafDomain
{
    my $domain_uuid = SF::MultiTenancy::getCurrentDomain();

    if (!(SF::MultiTenancy::isLeafDomain($domain_uuid)))
    {
        AddLog(SF::MultiTenancy::getCurrentDomainName(). " is not a leaf domain");
        return undef;
    }
    return SF::MultiTenancy::getNetmapNum($domain_uuid);
}

sub getCurrentNetmapNum
{
    my $domain_uuid = SF::MultiTenancy::getCurrentDomain();

    return SF::MultiTenancy::getNetmapNum($domain_uuid);
}

sub get3rdPartyMapUUIDByName
{
    my ($name, $domain_uuid) = @_;

    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");

    my $sql = "SELECT uuid FROM rna_user_3rd_party_map_name WHERE name=? AND domain_uuid IN (";
    my @domain_list = SF::MultiTenancy::getAncestorDomains(0, $domain_uuid);
    foreach my $domain (@domain_list)
    {
        $sql .= "uuid_atob('$domain'), ";
    }
    $sql .= "uuid_atob('$domain_uuid'))";
    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute($name) || throw Error::Simple("Database Error: ".$sth->errstr);
    my ($uuid) = $sth->fetchrow_array();

    return ($uuid);
}

sub get3rdPartyMapByName
{
    my ($name, $domain_uuid) = @_;

    if (defined($SF::SFDataCorrelator::HostInput::map_hash->{$name.$domain_uuid}))
    {
        return $SF::SFDataCorrelator::HostInput::map_hash->{$name.$domain_uuid};
    }

    my $uuid = get3rdPartyMapUUIDByName($name, $domain_uuid);

    return undef if (!defined($uuid));
    my $obj = SF::EOHandler::loadObject( $uuid );

    my $map;
    if ($obj)
    {
        $map = $obj->{data};
    }

    $SF::SFDataCorrelator::HostInput::map_hash->{$name.$domain_uuid} = $map;

    return $map;
}

sub SetCurrent3rdPartyMap
{
    my ($map_name, $domain_uuid) = @_;

    $SF::SFDataCorrelator::HostInput::__current_map = get3rdPartyMapByName($map_name, $domain_uuid);

    if (!defined($SF::SFDataCorrelator::HostInput::__current_map))
    {
        AddLog("Failed to find map '$map_name'");
        return -1;
    }
    return 0;
}

sub UnsetCurrent3rdPartyMap
{
    $SF::SFDataCorrelator::HostInput::__current_map = undef;
}

sub currentMapIsSet
{
    return (defined($SF::SFDataCorrelator::HostInput::__current_map));
}

sub SetCurrentSource
{
    my ($source_type,$name,$opt) = @_;

    $SF::SFDataCorrelator::HostInput::__current_source_id = GetSourceIDByName($source_type,
                                                                              $name,$opt);
}

sub SourceSet
{
    return defined($SF::SFDataCorrelator::HostInput::__current_source_id);
}

sub GetCurrentSource
{
    return ($SF::SFDataCorrelator::HostInput::__current_source_id);
}

sub getCriticalityByName
{
    my ($name) = @_;

    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");

    my $sql = "SELECT criticality FROM rna_criticality_str WHERE criticality_name=?";
    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute($name) || throw Error::Simple("Database Error: ".$sth->errstr);

    my ($num) = $sth->fetchrow_array();

    return ($num);
}

sub getNetProtoIDByName
{
    my ($name) = @_;

    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");

    my $sql = "SELECT protocol FROM rna_network_protocol_str WHERE protocol_name=?";
    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute($name) || throw Error::Simple("Database Error: ".$sth->errstr);

    my ($num) = $sth->fetchrow_array();

    return ($num);
}

sub getAttributeType
{
    my ($id) = @_;

    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");

    my $sql = "SELECT type FROM rna_attribute WHERE id=?";
    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute($id) || throw Error::Simple("Database Error: ".$sth->errstr);

    my ($type) = $sth->fetchrow_array();

    return ($type);
}

sub getAttributeTypeByName
{
    my ($name) = @_;

    # Special case for criticality
    if ($name =~ /criticality/i)
    {
        return getPkgVar( "SF::SFDataCorrelator::UserMessage", '$RNA_ATTR_TYPE_LIST');
    }

    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");

    my $sql = "SELECT type FROM rna_attribute WHERE name=?";
    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute($name) || throw Error::Simple("Database Error: ".$sth->errstr);

    my ($type) = $sth->fetchrow_array();

    return ($type);
}

sub getAttributePair
{
    my ($attr_name, $attr_value) = @_;

    my $attrib_id;
    my $attrib_value;

    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");

    my $sql = "SELECT id,type FROM rna_attribute WHERE name=?";
    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute($attr_name) || throw Error::Simple("Database Error: ".$sth->errstr);

    my ($id,$type) = $sth->fetchrow_array();

    $attrib_id = $id;

    if (defined($id) && defined($type) && defined($attr_value))
    {
        if ($type == getPkgVar( "SF::SFDataCorrelator::UserMessage", '$RNA_ATTR_TYPE_LIST'))
        {
            $sql = "SELECT item_id FROM rna_attribute_list_values WHERE id=? AND name=?";
            $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
            $sth->execute($id, $attr_value) || throw Error::Simple("Database Error: ".$sth->errstr);

            my ($list_id) = $sth->fetchrow_array();
            $attrib_value = $list_id;
        }
        else
        {
            $attrib_value = $attr_value;
        }
    }

    return ($attrib_id, $attrib_value);
}

sub ApplyFixMap
{
    my ($fixes, $map) = @_;

    my $fix_list;

    foreach my $fix_id (@$fixes)
    {
        my $added = 0;

        if (defined($map))
        {
            my $map_list = $map->{fix_map_list};

            if (defined($map_list->{$fix_id}))
            {
                my $maps = $map_list->{$fix_id}{fix};

                # If we have a map entry for this fix, call it "added"
                $added = 1;

                #warn "maps = " . Dumper($maps);
                foreach my $rna_fix (keys %$maps)
                {
                    push @$fix_list, $rna_fix;
                    #warn "fix $fix_id mapped to rna_fix_id : $rna_fix";
                }
                #return $map_list->{$fix_id};
            }
        }

        # If we couldn't find a match for this fix, add it to the list "as-is"
        if (!$added)
        {
            if ($fix_id  =~ /^\d+$/)
            {
                push @$fix_list, $fix_id;
            }
            else
            {
                #warn "attempting to lookup rna ID for fix $fix_id";

                my $id = GetFixIDByName($fix_id);

                if (defined($id))
                {
                    #warn "got fix_id $id for $fix_id";

                    push @$fix_list, $id;
                }
            }
        }
    }

    return $fix_list;
}

sub ApplyProductMap
{
    my ($prod, $map) = @_;

    if (defined($map))
    {
        my $map_list = $map->{product_map_list};

        my $key = $prod->{vendor_str} . ":" . $prod->{product_str} . ":" . $prod->{version_str};

        if (defined($map_list->{$key}))
        {
            my $item = $map_list->{$key};

            $prod->{vendor_id} = $item->{VDB_vendor_id};
            $prod->{product_id} = $item->{VDB_product_id};
            $prod->{major} = $item->{VDB_major};
            $prod->{minor} = $item->{VDB_minor};
            $prod->{revision} = $item->{VDB_revision};
            $prod->{build} = $item->{VDB_build};
            $prod->{patch} = $item->{VDB_patch};
            $prod->{extension} = $item->{VDB_extension};
        }

    }
}

# XXX: Currently handles only ip address specifications
sub SetOS
{
    my ($source_type, $uid, $addr_string, $os, $netmap_num) = @_;

    my $return = 0;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    #warn "ip = $addr_string";
    #warn "pre-map: os structure = " . Dumper($os);

    # There are race conditions with the creation os UserOSDef entries.
    # Lock access so that only one instance will run at a time.
    # Further details in bug 56998
    my $lockfile = SF::Reloc::RelocateFilename("/var/tmp/HostInput-SetOS.lock");
    open my $LOCK, ">>", $lockfile;
    SF::Util::lock($LOCK);

    try {
        ApplyProductMap($os, $SF::SFDataCorrelator::HostInput::__current_map);

        if (!$os->{fixes_already_remapped})
        {
            my $fixes = $os->{fixes};
            $os->{fixes} = ApplyFixMap($fixes, $SF::SFDataCorrelator::HostInput::__current_map);
        }
        #warn "post-map: os structure = " . Dumper($os);

        my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

        #warn "OS = " . Dumper($os);
        my $uuid = $os->{uuid};

        # Try to determine if a uuid already exists for this os def
        if (!$os->{drop_user_product})
        {
            my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");
            my $sql;
            my $sth;

            my @args;

            # If a software_id was specified, fill in the OS structure based on the parameters
            if ($os->{software_id})
            {
                my $get_sql = "select vendor_id,product_id,major,minor,build,patch,extension from rna_software_list where software_id=?";

                $sth = $dbh->prepare($get_sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
                $sth->execute($os->{software_id}) || throw Error::Simple("Database Error: ".$sth->errstr);

                my $sw = $sth->fetchrow_hashref();

                if ($sw && $sw->{vendor_id} && $sw->{product_id})
                {
                    $os->{vendor_id} = $sw->{vendor_id};
                    $os->{product_id} = $sw->{product_id};
                    $os->{major} = $sw->{major};
                    $os->{minor} = $sw->{minor};
                    $os->{revision} = $sw->{revision};
                    $os->{build} = $sw->{build};
                    $os->{patch} = $sw->{patch};
                    $os->{extension} = $sw->{extension};
                    $os->{to_major} = undef;
                    $os->{to_minor} = undef;
                    $os->{to_revision} = undef;
                }
            }

            $sql = "select uuid from rna_user_os_def where vendor_id=? and product_id=?";
            if ($os->{vendor_id} && $os->{product_id})
            {
                push @args, $os->{vendor_id};
                push @args, $os->{product_id};

                if (defined($os->{major}) && $os->{major} ne "")
                {
                    $sql .= " and major=?";
                    push @args, $os->{major};
                }
                else
                {
                    $sql .= " and (major='' or major IS NULL)";
                }
                if (defined($os->{minor}) && $os->{minor} ne "")
                {
                    $sql .= " and minor=?";
                    push @args, $os->{minor};
                }
                else
                {
                    $sql .= " and (minor='' or minor IS NULL)";
                }
                if (defined($os->{revision}) && $os->{revision} ne "")
                {
                    $sql .= " and revision=?";
                    push @args, $os->{revision};
                }
                else
                {
                    $sql .= " and (revision='' or revision IS NULL)";
                }
                if (defined($os->{to_major}) && $os->{to_major} ne "")
                {
                    $sql .= " and to_major=?";
                    push @args, $os->{to_major};
                }
                else
                {
                    $sql .= " and (to_major='' or to_major IS NULL)";
                }
                if (defined($os->{to_minor}) && $os->{to_minor} ne "")
                {
                    $sql .= " and to_minor=?";
                    push @args, $os->{to_minor};
                }
                else
                {
                    $sql .= " and (to_minor='' or to_minor IS NULL)";
                }
                if (defined($os->{to_revision}) && $os->{to_revision} ne "")
                {
                    $sql .= " and to_revision=?";
                    push @args, $os->{to_revision};
                }
                else
                {
                    $sql .= " and (to_revision='' or to_revision IS NULL)";
                }
                if (defined($os->{build}) && $os->{build} ne "")
                {
                    $sql .= " and build=?";
                    push @args, $os->{build};
                }
                else
                {
                    $sql .= " and (build='' or build IS NULL)";
                }
                if (defined($os->{patch}) && $os->{patch} ne "")
                {
                    $sql .= " and patch=?";
                    push @args, $os->{patch};
                }
                else
                {
                    $sql .= " and (patch='' or patch IS NULL)";
                }
                if (defined($os->{extension}) && $os->{extension} ne "")
                {
                    $sql .= " and extension=?";
                    push @args, $os->{extension};
                }
                else
                {
                    $sql .= " and (extension='' or extension IS NULL)";
                }
            }

            #warn "sql = $sql";
            #warn "args = " . Dumper(\@args);

            # If we have arguments set (there was either a product def or a software_id)
            if (@args)
            {
                $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
                $sth->execute(@args) || throw Error::Simple("Database Error: ".$sth->errstr);

                ($uuid) = $sth->fetchrow_array();
            }

            if ($uuid && $uuid ne "")
            {
                #warn "got uuid $uuid";
                $os->{uuid} = $uuid;
            }
            else
            {
                if ($os->{vendor_id} && $os->{product_id})
                {
                    # Didn't find an existing entry for this definition - create a new EO and return the new uuid
                    my $obj =  SF::EOHandler::newObject( "UserOSDef" );

                    $os->{uuid} = $obj->{uuid};
                    #warn "Didn't find an existing entry for this definition - create a new EO and return the new uuid $os->{uuid}";

                    # Set the actual vendor, product, and version strings if they are not set already
                    if (!defined($os->{'actual_vendor_str'}) &&
                        !defined($os->{'actual_vendor_str'}) &&
                        !defined($os->{'actual_vendor_str'}))
                    {
                        my ($new_vendor, $new_product, $new_version) = SF::RNA::Vulnerabilities::getVDBStrings( $os->{'vendor_id'},
                                                                                                    $os->{'product_id'},
                                                                                                    $os->{'major'},
                                                                                                    $os->{'minor'},
                                                                                                    $os->{'revision'},
                                                                                                    $os->{'build'},
                                                                                                    $os->{'patch'},
                                                                                                    $os->{'extension'});

                        $os->{'actual_vendor_str'} = $new_vendor;
                        $os->{'actual_product_str'} = $new_product;
                        $os->{'actual_version_str'} = $new_version;
                    }

                    # Store the actual vendor, product, and version strings for this entry
                    my $orig_vendor_str = $os->{'vendor_str'};
                    my $orig_product_str = $os->{'product_str'};
                    my $orig_version_str = $os->{'version_str'};

                    $os->{'vendor_str'} = $os->{'actual_vendor_str'};
                    $os->{'product_str'} = $os->{'actual_product_str'};
                    $os->{'version_str'} = $os->{'actual_version_str'};

                    $obj->{data} = $os;
                    SF::EOHandler::storeObject($obj);
                    $os->{is_new} = 1;

                    # Reset the users vendor, product, and version strings for passing to the backend
                    $os->{'vendor_str'} = $orig_vendor_str;
                    $os->{'product_str'} = $orig_product_str;
                    $os->{'version_str'} = $orig_version_str;
                }
            }
        }

        if (defined($os->{'product_str'}) || defined($os->{'vendor_str'}) || defined($os->{'version_str'}) || $os->{drop_user_product})
        {
            # set the OS (correlator call)
            $return = _SetOS( $source_type, $uid, $address_list, $os, $netmap_num, $has_host_id );

            # tell the other side to do this as well...
            if( SF::COOP::enabled() && $do_sync)
            {
                $address_list = ($has_host_id) ? $ip_addr_list : $address_list;
                SF::COOP::add_ha_transaction( \&_SetOS, { args => [ $source_type, $uid, $address_list, $os, $netmap_num, 0] }, "Set Custom OS Definition", 10 );
            }
        }
    } finally {
        SF::Util::unlock($LOCK);
        close $LOCK;
    };

    return $return;
}

sub _SetOS
{
    my ($source_type, $uid, $address_list, $os, $netmap_num, $has_host_id) = @_;

    #warn "UserProduct suggesting uuid $os->{uuid}";
    #warn "OS def = " . Dumper($os);

    # tell the correlator to set the os definitions for these hosts.
    my $data = SF::SFDataCorrelator::UserMessage::BuildSetOSEvent($source_type, $uid, $address_list, $os, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage($data);

    return $return;
}

sub AddFix
{
    my ($source_type, $uid, $addr_string, $port, $proto, $fix) = @_;

    my $netmap_num = getCurrentLeafDomain();
    if (!defined($netmap_num))
    {
        return -1;
    }

    my $host_id = SF::RNA::Hosts::getHostIdFromIp($addr_string, $netmap_num);
    if (!defined($host_id))
    {
        return -1;
    }

    my $fixes = SF::RNA::Hosts::GetFixes($host_id, $port, $proto);
    my $rval;

    #warn "current fixes = " . Dumper($fixes);

    # Since fixes are stored as RNA fix_ids, not 3rd party IDs, we need to convert the current ID and disable fix-remapping
    # when we call the SetOS/SetService function so we don't try to remap the already-RNA fix_ids
    my $fix_id_list = ApplyFixMap([$fix], $SF::SFDataCorrelator::HostInput::__current_map);

    foreach my $new_fix (@$fix_id_list)
    {
        # Add the current fix to the list
        push @$fixes, $new_fix;
    }

    #warn "new fixes = " . Dumper($fixes);

    my $def;
    $def->{port} = $port;
    $def->{proto} = $proto;
    $def->{fixes} = $fixes;
    $def->{fixes_already_remapped} = 1;

    if (!$def->{port})
    {
        $rval = SF::SFDataCorrelator::HostInput::SetOS($source_type, $uid, $addr_string, $def, $netmap_num);
    }
    else
    {
        $rval = SF::SFDataCorrelator::HostInput::SetService($source_type, $uid, $addr_string, $def, $netmap_num);
    }

    return $rval;
}

sub RemoveFix
{
    my ($source_type, $uid, $addr_string, $port, $proto, $fix) = @_;

    my $netmap_num = getCurrentLeafDomain();
    if (!defined($netmap_num))
    {
        return -1;
    }

    my $host_id = SF::RNA::Hosts::getHostIdFromIp($addr_string, $netmap_num);
    if (!defined($host_id))
    {
        return -1;
    }

    my $old_fixes = SF::RNA::Hosts::GetFixes($host_id, $port, $proto);
    my $rval;

    my $fix_id_list = ApplyFixMap([$fix], $SF::SFDataCorrelator::HostInput::__current_map);

    my $fixes;
    foreach my $id (@$old_fixes)
    {
        my $add_it = 1;

        foreach my $d_fix (@$fix_id_list)
        {
            if ($id == $d_fix)
            {
                # Don't add it - we found a match in our delete list
                $add_it = 0;
            }
        }
        if ($add_it)
        {
            push @$fixes, $id;
        }
    }

    my $def;
    $def->{port} = $port;
    $def->{proto} = $proto;
    $def->{fixes} = $fixes;

    if (!$def->{port})
    {
        $rval = SF::SFDataCorrelator::HostInput::SetOS($source_type, $uid, $addr_string, $def, $netmap_num);
    }
    else
    {
        $rval = SF::SFDataCorrelator::HostInput::SetService($source_type, $uid, $addr_string, $def, $netmap_num);
    }

    return $rval;
}

sub UnsetOS
{
    my ($source_type, $uid, $addr_string, $netmap_num) = @_;
    my $os = { drop_user_product => 1 };
    return SF::SFDataCorrelator::HostInput::SetOS($source_type, $uid, $addr_string, $os, $netmap_num);
}

sub UnsetService
{
    my ($source_type, $source_id, $addr_string, $port, $protocol, $netmap_num) = @_;
    my $service = {
                    drop_user_product => 1,
                    proto => $protocol,
                    port => $port,
                  };

    return SF::SFDataCorrelator::HostInput::SetService($source_type, $source_id, $addr_string, $service, $netmap_num);
}

sub SetService
{
    my ($source_type, $uid, $addr_string, $service, $netmap_num) = @_;

    #warn "ip = $addr_string";
    #warn "service structure = " . Dumper($service);

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    ApplyProductMap($service, $SF::SFDataCorrelator::HostInput::__current_map);

    if (!$service->{fixes_already_remapped})
    {
        my $fixes = $service->{fixes};
        $service->{fixes} = ApplyFixMap($fixes, $SF::SFDataCorrelator::HostInput::__current_map);
    }

    # If the service_id isn't defined but a service_name is defined, look the ID up.
    # Create an ID if none exists for this service
    if (!defined($service->{service_id}) && defined($service->{service_name}))
    {
        # A non-number was passed in; look up the ID
        $service->{service_id} = SF::RNA::AppID::GetAppIDByName($service->{service_name});
        # If the app does not exist, create it with default values
        if(!$service->{service_id}){
            my $app = {
                appName => $service->{service_name},
                appDescription => "$service->{service_name} Service",
                risk_index => 1,
                productivity_index => 1,
                serviceId => -1,
            };

            SF::RNA::AppID::SaveCustomApp($app);
            $service->{service_id} = $app->{appId};
        }
    }

    my $data = SF::SFDataCorrelator::UserMessage::BuildSetServiceEvent($source_type, $uid, $address_list, $service, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage($data);
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $service_dumped = Data::Dumper::Dumper( $service );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildSetServiceEvent($source_type,$uid,eval(\"$addr_list_dumped\"), eval(\"$service_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    return $return;
}

sub AddService
{
    my ($source_type, $uid, $addr_string, $service, $netmap_num) = @_;

    #warn "ip = $addr_string";
    #warn "service structure = " . Dumper($service);

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    #warn "ip list = " . Dumper($ip_address_list);

    ApplyProductMap($service, $SF::SFDataCorrelator::HostInput::__current_map);

    # If the service_id isn't defined but a service_name is defined, look the ID up.
    # Create an ID if none exists for this service
    if (!defined($service->{service_id}) && defined($service->{service_name}))
    {
        # A non-number was passed in; look up the ID
        $service->{service_id} = SF::RNA::AppID::GetAppIDByName($service->{service_name});
        # If the app does not exist, create it with default values
        if(!$service->{service_id}){
            my $app = {
                appName => $service->{service_name},
                appDescription => "$service->{service_name} Service",
                risk_index => 1,
                productivity_index => 1,
                serviceId => -1,
            };

            SF::RNA::AppID::SaveCustomApp($app);
            $service->{service_id} = $app->{appId};
        }
    }

    my $data = SF::SFDataCorrelator::UserMessage::BuildAddServiceEvent($source_type, $uid, $address_list, $service, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage($data);
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $service_dumped = Data::Dumper::Dumper( $service );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildAddServiceEvent($source_type,$uid,eval(\"$addr_list_dumped\"), eval(\"$service_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    return $return;
}

sub DeleteService
{
    #my ($ip,$port,$proto,$uid) = @_;
    my ($source_type, $uid, $addr_string, $port, $proto, $netmap_num) = @_;
    my @svc_list;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my %hsh;
    $hsh{'port'} = $port;
    $hsh{'proto'} = 6 if( $proto eq 'tcp' );
    $hsh{'proto'} = 17 if( $proto eq 'udp' );

    push( @svc_list, \%hsh );

    my $data = SF::SFDataCorrelator::UserMessage::BuildDeleteServiceEvent( $source_type, $uid, $address_list, , \@svc_list, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $svclist_dumped = Data::Dumper::Dumper( \@svc_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildDeleteServiceEvent($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$svclist_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    ## XXX: This isn't right...
    #my $ip = SF::Render::render('ip',$addr_string);
    #SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Deleting service on $ip.");

    return $return;
}

sub DeleteServiceList
{
    my ($source_type, $uid, $list, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my $data = SF::SFDataCorrelator::UserMessage::BuildDeleteServiceListEvent($source_type, $uid, $list ,$netmap_num);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $list_dumped = Data::Dumper::Dumper( $list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildDeleteServiceListEvent($source_type, $uid, eval(\"$list_dumped\"), $netmap_num) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Deleting service(s)");
}

sub DeleteClientApp
{
    my ($source_type, $uid, $addr_string, $id, $app_proto, $version, $netmap_num) = @_;
    my @ip_list;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my %hsh;
    # Allow $id and $type to be strings. Lookup the integer IDs for these if strings are passed in.
    if ($id  =~ /^\d+$/)
    {
        $hsh{'id'} = $id;
    }
    else
    {
        # A non-number was passed in; look up the ID
        $hsh{'id'} = SF::RNA::AppID::GetAppIDByName($id);
        # If the app does not exist, create it with default values
        if(!$hsh{'id'}){
            my $app = {
                appName => $id,
                appDescription => "$id Client",
                risk_index => 1,
                productivity_index => 1,
                clientAppId => -1,
            };

            SF::RNA::AppID::SaveCustomApp($app);
            $hsh{'id'} = $app->{appId};
        }
    }

    $hsh{'type'} = $app_proto;
    $hsh{'version'} = $version;

    push( @ip_list, \%hsh );

    my $data = SF::SFDataCorrelator::UserMessage::BuildDeleteClientAppEvent( $source_type, $uid, $address_list, \@ip_list, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $iplist_dumped = Data::Dumper::Dumper( \@ip_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildDeleteClientAppEvent($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$iplist_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    ## XXX: This isn't right
    #my $ip = SF::Render::render('ip',$addr_string);
    #SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Deleting client app on $ip.");

    #warn "DoUserMessage returned $return";

    return $return;
}

sub DeleteClientAppPayload
{
    my ($source_type, $uid, $addr_string, $id, $app_proto, $version, $payload_type, $payload_id, $netmap_num) = @_;
    my @ip_list;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my %hsh;
    # Allow $id and $type to be strings. Lookup the integer IDs for these if strings are passed in.
    if ($id  =~ /^\d+$/)
    {
        $hsh{'id'} = $id;
    }
    else
    {
        # A non-number was passed in; look up the ID
        $hsh{'id'} = SF::RNA::AppID::GetAppIDByName($id);
    }

    $hsh{'type'} = $app_proto;
    $hsh{'version'} = $version;

    if ($payload_type  =~ /^\d+$/)
    {
        $hsh{'payload_type'} = $payload_type;
    }
    else
    {
        # A non-number was passed in; look up the ID
        $hsh{'payload_type'} = SF::RNA::AppID::GetAppIDByName($payload_type);
    }

    if ($payload_id  =~ /^\d+$/)
    {
        $hsh{'payload_id'} = $payload_id;
    }
    else
    {
        # A non-number was passed in; look up the ID
        $hsh{'payload_id'} = SF::RNA::AppID::GetAppIDByName($payload_id);
    }

    push( @ip_list, \%hsh );

    my $data = SF::SFDataCorrelator::UserMessage::BuildDeleteClientAppPayloadEvent( $source_type, $uid, $address_list, \@ip_list, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $iplist_dumped = Data::Dumper::Dumper( \@ip_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildDeleteClientAppPayloadEvent($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$iplist_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    ## XXX: This isn't right
    #my $ip = SF::Render::render('ip',$addr_string);
    #SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Deleting client app on $ip.");

    #warn "DoUserMessage returned $return";

    return $return;
}

sub DeleteProtocol
{
    my ($source_type, $uid, $addr_string, $mac_list, $proto, $type, $netmap_num) = @_;
    my @ip_list;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my %hsh;
    if( $type =~ /xport/i )
    {
        $hsh{'type'} = 1;
        if ($proto  =~ /^\d+$/)
        {
            $hsh{'proto'} = $proto;
        }
        else
        {
            $hsh{'proto'} = getprotobyname($proto);
            if(!defined $hsh{'proto'}){
                AddLog("Unknown proto '$proto'");
                return 1;
            }
        }
    }
    if( $type =~ /net/i )
    {
        $hsh{'type'} = 0;
        if ($proto  =~ /^\d+$/)
        {
            $hsh{'proto'} = $proto;
        }
        else
        {
            $hsh{'proto'} = getNetProtoIDByName($proto);
            if(!defined $hsh{'proto'}){
                AddLog("Unknown proto '$proto'");
                return 1;
            }
        }
    }
    push( @ip_list, \%hsh );

    #$hsh{'proto'} = $proto;
    #$hsh{'type'} = 1 if( $type eq 'xport' );
    #$hsh{'type'} = 0 if( $type eq 'net' );
    #push( @ip_list, \%hsh );

    my $data = SF::SFDataCorrelator::UserMessage::BuildDeleteProtocolEvent( $source_type, $uid, $address_list, $mac_list, \@ip_list, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $iplist_dumped = Data::Dumper::Dumper( \@ip_list );
        my $mac_addr_list_dumped = Data::Dumper::Dumper( $mac_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildDeleteProtocolEvent($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$mac_addr_list_dumped\"), eval(\"$iplist_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    ## XXX: This isn't right
    #my $ip = SF::Render::render('ip',$addr_string);
    #SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Deleting protocol on $ip.");

    return $return;
}

sub AddProtocol
{
    my ($source_type, $uid, $addr_string, $mac_list, $proto, $type, $netmap_num) = @_;
    my @ip_list;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my %hsh;
    if( $type =~ /xport/i )
    {
        $hsh{'type'} = 1;
        if ($proto  =~ /^\d+$/)
        {
            $hsh{'proto'} = $proto;
        }
        else
        {
            $hsh{'proto'} = getprotobyname($proto);
            if(!defined $hsh{'proto'}){
                AddLog("Unknown proto '$proto'");
                return 1;
            }
        }
    }
    if( $type =~ /net/i )
    {
        $hsh{'type'} = 0;
        if ($proto  =~ /^\d+$/)
        {
            $hsh{'proto'} = $proto;
        }
        else
        {
            $hsh{'proto'} = getNetProtoIDByName($proto);
            if(!defined $hsh{'proto'}){
                AddLog("Unknown proto '$proto'");
                return 1;
            }
        }
    }
    push( @ip_list, \%hsh );

    my $data = SF::SFDataCorrelator::UserMessage::BuildAddProtocolEvent( $source_type, $uid, $address_list, $mac_list, \@ip_list, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $iplist_dumped = Data::Dumper::Dumper( \@ip_list );
        my $mac_addr_list_dumped = Data::Dumper::Dumper( $mac_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildAddProtocolEvent($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$mac_addr_list_dumped\"), eval(\"$iplist_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    ## XXX: This isn't right
    #my $ip = SF::Render::render('ip',$addr_string);
    #SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Deleting protocol on $ip.");

    return $return;
}

sub DeleteHost
{
    my ($source_type, $uid, $addr_string, $mac_list, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my $data = SF::SFDataCorrelator::UserMessage::BuildDeleteAddrEvent( $source_type, $uid, $address_list, $mac_list, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $mac_addr_list_dumped = Data::Dumper::Dumper( $mac_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildDeleteAddrEvent($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$mac_addr_list_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    ## XXX: This isn't right
    #my $ip = SF::Render::render('ip',$addr_string);
    #SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Deleting host $ip.");

    return $return;
}

# This function is used by the automation team for product testing.
# If you change the arguments, output, or functionality of this function
# please open a bug:
#
# Product: Automation
# Component: ATF:Framework
# Subject should start with: SF_API Changes
#
sub DeleteUserIdentities
{
    my ($user_sessions,$uid) = @_;

    # tell the other side to do this as well
    if( SF::COOP::enabled() && $do_sync)
    {
        my $runCount = 10;

        # If this is the standby DC, it shouldn't be able to initiate the delete
        if ( !SF::PeerManager::PeerInfo::isActiveHA() )
        {
            return 0;
        }
        SF::COOP::add_ha_transaction( \&_DeleteUserIdentities, { args => [ $user_sessions, $uid ] }, "Delete User Identities", $runCount );
    }

    return _DeleteUserIdentities($user_sessions,$uid);
}

sub _DeleteUserIdentities
{
   my ($user_sessions,$uid) = @_;
   my $return = 0;

   my $channel = SF::SFDataCorrelator::UserMessage::OpenEventChannel();
   if( $channel )
   {
      foreach my $sess ( @$user_sessions )
      {
         my $data = SF::SFDataCorrelator::UserMessage::BuildDeleteUserIdentityEvent( $sess, $uid );
         my $returnStatus = SF::SFDataCorrelator::UserMessage::SendEvent( $channel, getPkgVar( "SF::MessageSocket", '$TYPE_DCEUserMessage'), $data );
         if( !defined $returnStatus )
         {
            $return = 1;
            last;
         }
      }
      SF::SFDataCorrelator::UserMessage::CloseEventChannel( $channel );
   }

   return $return;
}

sub AddHostAttribute
{
    my ($source_type, $uid, $attrib_name, $attrib_type) = @_;

    # tell the other side to do this as well...
    if( SF::COOP::enabled() && $do_sync )
    {
        SF::COOP::add_ha_transaction( \&_AddHostAttribute, { args => [ $source_type, $uid, $attrib_name, $attrib_type ] }, "Add Host Attribute", 10 );
    }
    return _AddHostAttribute($source_type, $uid, $attrib_name, $attrib_type);
}

sub _AddHostAttribute
{
    my ($source_type, $uid, $attrib_name, $attrib_type) = @_;

    my $hsh;

    # attribute name can only be alphanumeric (words) and spaces
    if ($attrib_name =~ /[^\w\s]/ )
    {
        AddLog("Invalid Attribute Name Syntax Entered: $attrib_name");
        return -1;
    }

    # get the attribute id if available
    my $id = SF::RNA::Hosts::getAttributeIDByName($attrib_name);

    # if $id exists, we don't need to create a new one
    return 0 if( $id );

    # otherwise generate a unique id and create the attribute
    $hsh->{uuid} = SF::Util::uuid();
    $hsh->{name} = $attrib_name;
    # Text type
    $hsh->{type} = $SF::SFDataCorrelator::UserMessage::RNA_ATTR_TYPE_TEXT if(lc($attrib_type) eq 'text');
    # URL type
    $hsh->{type} = $SF::SFDataCorrelator::UserMessage::RNA_ATTR_TYPE_URL if(lc($attrib_type) eq 'url');
    if( !defined($hsh->{type}) )
    {
        AddLog("Invalid Attribute Type: $attrib_type");
        return -1;
    }
    $hsh->{category} = $SF::SFDataCorrelator::UserMessage::ATTR_CATEGORY_USER;
    SF::RNA::Hosts::createAttrib($uid,$hsh);

    return 0;
}

sub DeleteHostAttribute
{
    my ($source_type, $uid, $attrib_name) = @_;

    my $id = SF::RNA::Hosts::getAttributeIDByName($attrib_name);
    # if not found, it's ok
    if( !$id )
    {
        AddLog("Can not Find Attribute Name '$attrib_name'");
        return 0;
    }
    my $attrib = SF::RNA::Hosts::GetAttributeByID($id);
    # we do not delete white list attribute
    if( $attrib->{name} =~ /^__(.*)$/ )
    {
        if( SF::Types::is_valid( 'uuid', $1 ) )
        {
            AddLog("Can not Delete White List Attribute: $attrib->{name}");
            return 0;
        }
    }

    my ($uuid, $rev_uuid) = getConfigedHostAttributeUUID($id,$attrib->{name});
    if( $uuid && SF::Types::is_valid('uuid',$uuid) )
    {
        # load UUID
        my $data = SF::EOHandler::loadObject($uuid,$rev_uuid);
        AddLog("Can not Delete Host Attribute '$attrib->{name}' - Attribute is Configured in $data->{type} '$data->{data}{name}'");
        return -1;
    }

    # tell the other side to do this as well...
    if( SF::COOP::enabled() && $do_sync )
    {
        SF::COOP::add_ha_transaction( \&_DeleteHostAttribute, { args => [ $source_type,$uid,$attrib_name,undef ] }, "Delete Host Attribute", 10 );
    }
    return _DeleteHostAttribute($source_type, $uid, $attrib_name, $attrib);
}

sub getConfigedHostAttributeUUID
{
    my ($id,$name) = @_;

    my $dbh = SF::SFDBI::connect(mysql_db => 0) || throw Error::Simple("Failed to connect to the database");
    my $result;

    # check if this attribute is configured in Compliance Rule with "Host profile Qualification"
    # if it is, we can not delete this attribute because it's still in use
    if( defined $id && defined $name && $id > 0 && $name ne '')
    {
        # access rna_policy_rules table
        my $sql = "SELECT name,code,uuid,rev_uuid FROM rna_policy_rules WHERE deleted=0";
        my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
        $sth->execute() || throw Error::Simple("Database Error: ".$sth->errstr);
        while( $result = $sth->fetchrow_arrayref() )
        {
            # Example: '((ids_event::true)) AND ((src_host::attr_3 == "vhfh"))'
            if( $result->[1] =~ /::attr_(\d+)/ )
            {
                my $attr_id = $1;
                if( $id == $attr_id )
                {
                    return ($result->[2],$result->[3]);  # return uuid and rev_uuid
                }
            }
        }
    }
    else
    {
        return (undef,undef);
    }

    # table lookup to see what we currently can configure (from UI) for Host Attribute
    my $tables = new SF::Events::Tables;
    my $tables_and_columns = $tables->GetTablesAndColumns('custom_tables');
    if( $tables_and_columns->{rna_attribute} )
    {
        # check if any custom tables have Host Attribute configured, if yes,
        # we can not delete this attribute because it's still in use
        my $sql = "SELECT column_name,tableview_id FROM custom_tableview_column WHERE table_name=?";
        my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
        $sth->execute('rna_attribute') || throw Error::Simple("Database Error: ".$sth->errstr);
        $result = $sth->fetchall_arrayref();
        foreach my $attr (@{$result})
        {
            if( $tables_and_columns->{rna_attribute}{columns}{$attr->[0]} eq $name )
            {
                return ($attr->[1],undef);
            }
        }
    }
    return (undef,undef);
}

sub _DeleteHostAttribute
{
    my ($source_type, $uid, $attrib_name, $attrib) = @_;
    my $ret;

    # Table rna_attribute: UUID is not the same for remote DC, we need to find the correct UUID and passed in
    if( !defined $attrib )
    {
        my $id = SF::RNA::Hosts::getAttributeIDByName($attrib_name);
        # if not found, it's ok
        if( !$id )
        {
            AddLog("Can not Find Attribute Name '$attrib_name'");
            return 0;
        }
        $attrib = SF::RNA::Hosts::GetAttributeByID($id);
    }
    my %hsh;
    $hsh{uuid} = $attrib->{uuid};
    $hsh{'name'} = $attrib->{name};
    $hsh{'type'} = $attrib->{type};
    $hsh{'id'} = $attrib->{id};
    return SF::RNA::Hosts::deleteAttrib($uid,\%hsh);
}

sub SetAttributeValue
{
    my ($source_type, $uid, $addr_string, $id, $value, $netmap_num) = @_;
    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    if ($id =~ /criticality/i)
    {
        return SetCriticality($source_type, $uid, $addr_string, $value, $netmap_num);
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my %hsh;
    if ($id  =~ /^\d+$/)
    {
        $hsh{id} = $id;
        $hsh{uuid} = SF::RNA::Hosts::getAttribUuidFromID( $id );
        $hsh{value} = $value;
    }
    else
    {
        my ($new_id, $new_value) = getAttributePair($id, $value);
        $hsh{id} = $new_id;
        $hsh{uuid} = SF::RNA::Hosts::getAttribUuidFromID( $new_id );
        $hsh{value} = $new_value;
    }

    my $type = getAttributeType($hsh{id});

    if( $type eq getPkgVar( "SF::SFDataCorrelator::UserMessage", '$RNA_ATTR_TYPE_TEXT') || $type eq getPkgVar( "SF::SFDataCorrelator::UserMessage", '$RNA_ATTR_TYPE_URL') )
    {
        $hsh{'type'} = 1;
    }
    else
    {
        $hsh{'type'} = 0;
    }

    my $return = actualSetAttributeValue( $source_type, $uid, $address_list, \%hsh, $netmap_num, $has_host_id);

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $hsh_dumped = Data::Dumper::Dumper( \%hsh );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::HostInput;
SF::SFDataCorrelator::HostInput::actualSetAttributeValue($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$hsh_dumped\"), $netmap_num, 0);
EOF
        SF::COOP::add_transaction( $thunk );
    }
    return $return;
}

sub actualSetAttributeValue
{
    my ( $source_type, $uid, $address_list, $hsh, $netmap_num, $has_host_id) = @_;

    $hsh->{id} = SF::RNA::Hosts::getAttribIDFromUuid( $hsh->{uuid} );

    my $data = SF::SFDataCorrelator::UserMessage::BuildSetAttributeValueEvent( $source_type, $uid, $address_list, $hsh, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    return $return;
}

sub DeleteAttributeValue
{
    my ($source_type, $uid, $addr_string, $id, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    if ($id =~ /criticality/i)
    {
        return SetCriticality($source_type, $uid, $addr_string, 0, $netmap_num);
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my %hsh;
    if ($id  =~ /^\d+$/)
    {
        $hsh{id} = $id;
        $hsh{uuid} = SF::RNA::Hosts::getAttribUuidFromID( $id );
    }
    else
    {
        ($hsh{id}) = getAttributePair($id);
        $hsh{uuid} = SF::RNA::Hosts::getAttribUuidFromID( $hsh{id} );
    }

    my $return = actualDeleteAttributeValue( $source_type, $uid, $address_list, \%hsh, $netmap_num, $has_host_id);

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $hsh_dumped = Data::Dumper::Dumper( \%hsh );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::HostInput;
SF::SFDataCorrelator::HostInput::actualDeleteAttributeValue($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$hsh_dumped\"), $netmap_num, 0);
EOF
        SF::COOP::add_transaction( $thunk );
    }

    return $return;
}

sub actualDeleteAttributeValue
{
    my ( $source_type, $uid, $address_list, $hsh, $netmap_num, $has_host_id) = @_;

    $hsh->{id} = SF::RNA::Hosts::getAttribIDFromUuid( $hsh->{uuid} );

    my $data = SF::SFDataCorrelator::UserMessage::BuildDeleteAttributeValueEvent( $source_type, $uid, $address_list, $hsh, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    return $return;
}

sub SetCriticality
{
    my ($source_type, $uid, $addr_string, $crit, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my $criticality = 0;
    if ($crit  =~ /^\d+$/)
    {
        $criticality = $crit;
    }
    else
    {
        $criticality = getCriticalityByName($crit);
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my $data = SF::SFDataCorrelator::UserMessage::BuildSetCriticalityEvent( $source_type, $uid, $address_list, $criticality, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildSetCriticalityEvent($source_type, $uid, eval(\"$addr_list_dumped\"),$criticality, $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Setting criticality");

    return $return;
}

sub SetInvalidVulns
{
    my ($source_type, $uid, $addr_string, $vulns, $vuln_type, $netmap_num) = @_;
    my @vuln_list;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    return if(!SF::Types::is_valid('vuln_type', $vuln_type));

    my $nessus_id = getPkgVar( 'SF::SFDataCorrelator::UserMessage', '$VULN_TYPE_NESSUS' );
    if ($vuln_type =~ /rna/i)
    {
        $vuln_type = getPkgVar( 'SF::SFDataCorrelator::UserMessage', '$VULN_TYPE_RNA' );
    }
    elsif ($vuln_type =~ /firesight/i)
    {
        $vuln_type = getPkgVar( 'SF::SFDataCorrelator::UserMessage', '$VULN_TYPE_FIRESIGHT' );
    }
    elsif ( $vuln_type =~ /nessus/i || $vuln_type eq "$nessus_id" )
    {
        $vuln_type = "$nessus_id";
    }
    else
    {
        my $domain_uuid = SF::MultiTenancy::getDomainForNetmap($netmap_num);
        my $uuid = get3rdPartyMapUUIDByName($vuln_type, $domain_uuid);
        if (defined($uuid))
        {
            my $obj = SF::EOHandler::loadObject( $uuid );

            my $list = $obj->{data}{vuln_map_list};
            #warn "list = " . Dumper($list);
            if ($list)
            {
                # Do User Input to add the vulns to the network map
                $vuln_type = 0;
                foreach my $vuln (@$vulns)
                {
                    $vuln->{uuid} = $uuid;
                    $vuln->{vuln_str} = $vuln->{vuln_id};
                    $vuln->{vuln_id} = undef;
                }
            }
            else
            {
                AddLog("unknown vuln type $vuln_type");
                return 1;
            }
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    foreach my $vuln (@$vulns)
    {
        $vuln->{'proto'} = 6 if( $vuln->{'proto'} && $vuln->{'proto'} =~ /tcp/i );
        $vuln->{'proto'} = 17 if( $vuln->{'proto'} && $vuln->{'proto'} =~ /udp/i );
    }

    my $data = SF::SFDataCorrelator::UserMessage::BuildVulnInvalidEvent( $source_type, $uid, $address_list, $vuln_type, $vulns, $netmap_num, $has_host_id);

    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $vuln_list_dumped = Data::Dumper::Dumper( $vulns );
        my $vuln_type_dumped = Data::Dumper::Dumper( $vuln_type );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildVulnInvalidEvent($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$vuln_type_dumped\"), eval(\"$vuln_list_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    ## XXX: This isn't right
    #my $ip = SF::Render::render('ip',$addr_string);
    #SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Disabling selected vulns on host $ip");

    return $return;
}

sub SetInvalidVulns_ex
{
    my ($source_type, $uid, $addr_string, $vulns, $vuln_type, $netmap_num) = @_;
    my @vuln_list;

    #Construct the vulnerability hashes for the selected vulnerabilities.
    foreach( @$vulns ){
        # Split has a field limit, as the version might have a : in it
        my ( $vuln_id,$port,$proto,$subservice,$client_app_id,$client_app_proto,$version ) = split /:/, $_, 7;
        my %hsh;

        $hsh{'port'} = $port;
        $hsh{'proto'} = 6 if( $proto eq 'tcp' );
        $hsh{'proto'} = 17 if( $proto eq 'udp' );
        $hsh{'subservice'} = $subservice;
        $hsh{'vuln_id'} = $vuln_id;
        $hsh{'client_app_id'} = $client_app_id;
        $hsh{'client_app_proto'} = $client_app_proto;
        $hsh{'version'} = $version;
        push( @vuln_list, \%hsh );
    }

    return SetInvalidVulns($source_type, $uid, $addr_string, \@vuln_list, $vuln_type, $netmap_num);
}

sub Reload3rdPartyVulns
{
    my ($source_type, $uid, $addr_string, $uuid, $netmap_num) = @_;
    my @vuln_list;

    if (!defined($uuid))
    {
        AddLog("unknown vuln type $uuid");
        return 1;
    }

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);
    my $vuln = { uuid=>$uuid };
    my $vulns;
    push @$vulns, $vuln;

    my $data = SF::SFDataCorrelator::UserMessage::BuildVulnValidEvent( $source_type, $uid, $address_list, $uuid, $vulns, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $vuln_list_dumped = Data::Dumper::Dumper( $vulns );

        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildVulnValidEvent($source_type, $uid, eval(\"$addr_list_dumped\"), $uuid, eval(\"$vuln_list_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    return $return;
}

sub SetValidVulns
{
    my ($source_type, $uid, $addr_string, $vulns, $vuln_type, $netmap_num) = @_;
    my @vuln_list;

    #return if(!SF::Types::is_valid('vuln_type', $vuln_type));

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my $nessus_id = getPkgVar( 'SF::SFDataCorrelator::UserMessage', '$VULN_TYPE_NESSUS' );
    if ($vuln_type =~ /rna/i)
    {
        $vuln_type = getPkgVar( 'SF::SFDataCorrelator::UserMessage', '$VULN_TYPE_RNA' );
    }
    elsif ($vuln_type =~ /firesight/i)
    {
        $vuln_type = getPkgVar( 'SF::SFDataCorrelator::UserMessage', '$VULN_TYPE_FIRESIGHT' );
    }
    elsif ( $vuln_type =~ /nessus/i || $vuln_type eq "$nessus_id" )
    {
        $vuln_type = "$nessus_id";
    }
    else
    {
        my $domain_uuid = SF::MultiTenancy::getDomainForNetmap($netmap_num);
        my $uuid = get3rdPartyMapUUIDByName($vuln_type, $domain_uuid);
        if (defined($uuid))
        {
            my $obj = SF::EOHandler::loadObject( $uuid );

            my $list = $obj->{data}{vuln_map_list};
            #warn "list = " . Dumper($list);
            if ($list)
            {
                # Do User Input to add the vulns to the network map
                $vuln_type = 0;
                foreach my $vuln (@$vulns)
                {
                    $vuln->{uuid} = $uuid;
                    $vuln->{vuln_str} = $vuln->{vuln_id};
                    $vuln->{vuln_id} = undef;
                }
            }
            else
            {
                AddLog("unknown vuln type $vuln_type");
                return 1;
            }
        }

        #return 1;
        #$SF::SFDataCorrelator::HostInput::map_hash->{$vuln_type} = $map;
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    foreach my $vuln (@$vulns)
    {
        $vuln->{'proto'} = 6 if( $vuln->{'proto'} && $vuln->{'proto'} =~ /tcp/i );
        $vuln->{'proto'} = 17 if( $vuln->{'proto'} && $vuln->{'proto'} =~ /udp/i );
    }

    my $data = SF::SFDataCorrelator::UserMessage::BuildVulnValidEvent( $source_type, $uid, $address_list, $vuln_type, $vulns, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $vuln_list_dumped = Data::Dumper::Dumper( $vulns );
        my $vuln_type_dumped = Data::Dumper::Dumper( $vuln_type );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildVulnValidEvent($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$vuln_type_dumped\"), eval(\"$vuln_list_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    ## XXX: This isn't right
    #my $ip = SF::Render::render('ip',$addr_string);
    #SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Disabling selected vulns on host $ip");

    return $return;
}

sub SetValidVulns_ex
{
    my ($source_type, $uid, $addr_string, $vulns, $vuln_type, $netmap_num) = @_;
    my @vuln_list;

    #Construct the vulnerability hashes for the selected vulnerabilities.
    foreach( @$vulns ){
        # Split has a field limit, as the version might have a : in it
        my ( $vuln_id,$port,$proto,$subservice,$client_app_id,$client_app_proto,$version ) = split /:/, $_, 7;
        my %hsh;

        $hsh{'port'} = $port;
        $hsh{'proto'} = 6 if( $proto eq 'tcp' );
        $hsh{'proto'} = 17 if( $proto eq 'udp' );
        $hsh{'subservice'} = $subservice;
        $hsh{'vuln_id'} = $vuln_id;
        $hsh{'client_app_id'} = $client_app_id;
        $hsh{'client_app_proto'} = $client_app_proto;
        $hsh{'version'} = $version;
        push( @vuln_list, \%hsh );
    }

    return SetValidVulns($source_type, $uid, $addr_string, \@vuln_list, $vuln_type, $netmap_num);
}

sub DeleteVulnList
{
    my ($source_type, $uid, $vuln_type, $vuln_list, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my $data = SF::SFDataCorrelator::UserMessage::BuildVulnListInvalidEvent( $source_type, $uid, $vuln_type, $vuln_list, $netmap_num );
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $vuln_list_dumped = Data::Dumper::Dumper( $vuln_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildVulnListInvalidEvent( $source_type, $uid, $vuln_type, eval(\"$vuln_list_dumped\"), $netmap_num) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator", SF::Permission::getNameByID($uid), "Deleting vuln(s)");
    return $return;
}

sub AddClientApp
{
    my ($source_type, $uid, $addr_string, $id, $type, $version, $netmap_num) = @_;
    my @ip_list;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my %hsh;

    # Allow $id and $type to be strings. Lookup the integer IDs for these if strings are passed in.
    if ($id  =~ /^\d+$/)
    {
        $hsh{'id'} = $id;
    }
    else
    {
        # A non-number was passed in; look up the ID
        $hsh{'id'} = SF::RNA::AppID::GetAppIDByName($id);
        # If the app does not exist, create it with default values
        if(!$hsh{'id'}){
            my $app = {
                appName => $id,
                appDescription => "$id Client",
                risk_index => 1,
                productivity_index => 1,
                clientAppId => -1,
            };

            SF::RNA::AppID::SaveCustomApp($app);
            $hsh{'id'} = $app->{appId};
        }
    }

    $hsh{'type'} = 0;
    $hsh{'version'} = $version;

    push( @ip_list, \%hsh );

    my $data = SF::SFDataCorrelator::UserMessage::BuildAddClientAppEvent( $source_type, $uid, $address_list, \@ip_list, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $iplist_dumped = Data::Dumper::Dumper( \@ip_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildAddClientAppEvent($source_type, $uid, eval(\"$addr_list_dumped\"), eval(\"$iplist_dumped\"), $netmap_num, 0) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    ## XXX: This isn't right
    #my $ip = SF::Render::render('ip',$addr_string);
    #SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Deleting client app on $ip.");

    return $return;
}

sub AddHost
{
    my ($source_type, $uid, $ip_address, $mac_address) = @_;

    my $ip_address_list;
    my ($valid_ip,$valid_mac) = (SF::Types::is_valid('ip',$ip_address, {ipv4or6 => 1}),SF::Types::is_valid('mac',$mac_address));

    if( $valid_ip )  # valid IP case
    {
        if( $mac_address && !$valid_mac )
        {
            AddLog("Failed to recognize MAC address: $mac_address");
            return -1;
        }
        $ip_address_list = convertAddress($ip_address);
    }
    else  # invalid IP case
    {
        # if IP address is entered, raise error
        if( $ip_address )
        {
            AddLog("Failed to recognize IP address: $ip_address");
            return -1;
        }
        # if this comes out with an invalid MAC address, raise error
        if( !$valid_mac )
        {
            AddLog("Failed to recognize MAC address: $mac_address");
            return -1;
        }
    }
    $mac_address = '' if(!defined $mac_address); # to avoid warnings in sending AddHost to SFD

    my $netmap_num = getCurrentLeafDomain();
    if (!defined($netmap_num))
    {
        return -1;
    }

    my $data = SF::SFDataCorrelator::UserMessage::BuildAddAddrEvent( $source_type, $uid, $ip_address_list, [$mac_address], $netmap_num);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage( $data );
    if( $return != 0 )
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $ip_addr_list_dumped = Data::Dumper::Dumper( $ip_address_list );
        my $mac_addr_list_dumped = Data::Dumper::Dumper( [$mac_address] );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage( SF::SFDataCorrelator::UserMessage::BuildAddAddrEvent($source_type, $uid, eval(\"$ip_addr_list_dumped\"), eval(\"$mac_addr_list_dumped\"), $netmap_num) );
EOF
        SF::COOP::add_transaction( $thunk );
    }

    ## XXX: This isn't right
    #my $ip = SF::Render::render('ip',$addr_string);
    #SF::AuditLogMsg::AuditLogWrite("SFDataCorrelator",SF::Permission::getNameByID($uid),"Deleting host $ip.");

    return $return;
}

# Add an Nmap scan entry for this new domain.
sub CreateSourcesForNewDomain{
    my ($netmap_num) = @_;

    warn "CreateSourcesForNewDomain with netmap_num=$netmap_num";
    GetSourceIDByName($source_type_scan, 'Nmap', undef, undef, $netmap_num);
}


sub GetSourceIDByName
{
    my ($source_type,$name,$opt, $dbh, $netmap_num) = @_;

    if (defined($source_type) && $source_type < $source_type_scan)
    {
        return undef;
    }

    if (!defined($netmap_num))
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return undef;
        }
    }

    # use appropriate DB handle:
    if (!defined $dbh)
    {
    	$dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");
    }

    if ( $source_type == $source_type_scan )
    {
        my $rval = findScanTypeID($name,$opt, $dbh, $netmap_num);
        return $rval;
    }

    if (!defined($source_type))
    {
        $source_type = $source_type_app;
    }

    return findAppTypeID($name, $opt, $dbh, $netmap_num);
}

sub findAppTypeID
{
    my ($name, $flag, $dbh, $netmap_num) = @_;

    my $table_name = "rna_source_app_str";

    # already an ID !
    if( $name =~ /^\d+$/ )
    {
        return CheckSourceID($name,$dbh,$table_name,$netmap_num);
    }

    if (exists($app_ids->{$name.$netmap_num}))
    {
        return $app_ids->{$name.$netmap_num};
    }

    my $id = CheckSourceName($name, $dbh, $table_name, $netmap_num, $app_ids);
    if (defined($id))
    {
        return $id;
    }

    if ($name && $name ne "")
    {
        my $id = CreateNewSource($name, $dbh, $table_name, $netmap_num, $app_ids);
        if (defined ($id))
        {
            return $id;
        }
   }
   return undef;
}

sub CheckSourceID
{
    my ($id,$dbh,$table_name,$netmap_num) = @_;

    my $sql = "select name from $table_name where id = ?";
    my $sth = $dbh->prepare($sql) ||
    throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute($id) || throw Error::Simple("Database Error: ".$sth->errstr);
    my ($name) = $sth->fetchrow_array();
    my $source_type_name;

    if (defined($name))
    {
        if ($table_name eq 'rna_source_app_str')
        {
            $source_type_name = $source_type_app;
        }
        else
        {
            $source_type_name = $source_type_scan;
        }

        # ID exists in the type table,
        # check if the ID exists for the given netmap
        $sql = "select
                    source_id
                from
                    rna_source_id_priority
                where
                    source_type = ?
                    and source_id = ?
                    and netmap_num = ?
                    and deleted=0";

        my $sth = $dbh->prepare($sql)                      || throw Error::Simple("Database Error: ".$dbh->errstr);
        $sth->execute($source_type_name, $id, $netmap_num) || throw Error::Simple("Database Error: ".$sth->errstr);
        my ($source_id) = $sth->fetchrow_array();

        if (defined ($source_id)){
            return $id;
        }
    }
    # ID does not exist for the given netmap, reject it
    return undef;
}

sub CheckSourceName
{
    my ($name,$dbh,$table_name,$netmap_num,$list) = @_;

    # search for the name, case sensitive search
    my $sql = "SELECT id FROM $table_name WHERE CAST(name AS BINARY) = CAST('$name' AS BINARY)";
    my $sth = $dbh->prepare($sql) ||
    throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute() || throw Error::Simple("Database Error: ".$sth->errstr);
    my ($id) = $sth->fetchrow_array();

    my $source_type_name;
    # Source Name exists in the type table
    if (defined($id))
    {
        if ($table_name eq 'rna_source_app_str')
        {
            $source_type_name = $source_type_app;
        }
        else
        {
            $source_type_name = $source_type_scan;
        }

        # Check if the ID exists for the given netmap
        my $sql = " select
                        source_id
                    from
                        rna_source_id_priority
                    where
                        source_type = ?
                        AND source_id = ?
                        AND netmap_num = ?
                        AND deleted=0";

        my $sth = $dbh->prepare($sql) ||
        throw Error::Simple("Database Error: ".$dbh->errstr);
        $sth->execute($source_type_name, $id, $netmap_num) || throw Error::Simple("Database Error: ".$sth->errstr);
        my ($source_id) = $sth->fetchrow_array();

        if (defined($source_id))
        {
            $list->{$name.$netmap_num} = $id;
            return $id;
        }

        # Name exists for another netmap, use the same ID to insert an entry for the given netmap
        _InsertIntoPriorityTable($source_type_name, $id, $dbh, $netmap_num);
        SF::NetworkDiscovery::addSource($source_type_name, $id, $name, $netmap_num);

        $list->{$name.$netmap_num} = $id;

        return $id;
    }
    return undef;
}

sub CreateNewSource
{
    my ($name,$dbh,$table_name,$netmap_num,$list,$has_vuln_info) = @_;

    warn "CreateNewSource called with name=$name, table_name=$table_name, netmap_num=$netmap_num";

    # No existing ID was found; create a new one
    my $id = SF::HA::FindNextIncrement($table_name);

    my $source_type_name;
    if (defined($id))
    {
        # Write the new service_id to the type table

        my $sql;

        if ($table_name eq 'rna_source_app_str')
        {
            $source_type_name = $source_type_app;
            $sql = "INSERT INTO $table_name SET id=$id,name='$name'";
        }
        else
        {
            $source_type_name = $source_type_scan;
            $sql = "INSERT INTO $table_name SET id=$id,name='$name',has_vuln_info=$has_vuln_info";
        }

        my $sth = $dbh->prepare($sql) || die "can't prepare db\n";
        $sth->execute();

        # Insert the new source into rna_source_id_priority table
        _InsertIntoPriorityTable($source_type_name, $id, $dbh, $netmap_num);
        SF::NetworkDiscovery::addSource($source_type_name, $id, $name, $netmap_num);

        $list->{$name.$netmap_num} = $id;
    }
    return $id;
}

sub _InsertIntoPriorityTable
{
    my ($source_type_name, $id, $dbh, $netmap_num) = @_;
    # Find the largest priority in the table and assign the next largest value to the new row.
    my $sql = "
        insert into
            rna_source_id_priority (
                netmap_num,
                source_type,
                source_id,
                priority
            )
        select
            ?,?,?,
            coalesce(max(rsip.priority),0)+1
        from
            rna_source_id_priority rsip
        where
            rsip.source_type in (2,3)
            AND rsip.netmap_num = ?";

    my $sth = $dbh->prepare($sql)                                   || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute($netmap_num,$source_type_name,$id,$netmap_num)    || throw Error::Simple("Database Error: ".$sth->errstr);
}

sub GetAllSourceIDs
{
    my $only_valid = @_;
    my $scan_types = GetScanTypes();
    my $app_source_types = GetAppSourceTypes();
    my $user_ids = GetUserIDs();

    my $all = [];
    foreach my $type (@$scan_types)
    {
        my $id = $type->{'id'};
        push( @$all, { id => "2:$id", name => SF::i18n::get_pm_msg("scan_type", 'main') . " " . $type->{name}, netmap_num => $type->{netmap_num} } );
    }
    foreach my $type (@$app_source_types)
    {
        my $id = $type->{'id'};
        push( @$all, { id => "3:$id", name => SF::i18n::get_pm_msg("app_type", 'main') . " " . $type->{name}, netmap_num => $type->{netmap_num} } );
    }
    foreach my $type (@$user_ids)
    {
        my $id = $type->{'id'};
        if($only_valid && $id != 2 && $id != 3){ # ignore mbuser and report if only_valid is passed
                  push( @$all, { id => "1:$id", name => SF::i18n::get_pm_msg("user_type", 'main') . " " . $type->{name}, domain_uuid => $type->{domain_uuid} } );
        }
    }

    return $all;
}

sub GetScanTypeByName
{
    my ($name) = @_;

    return (undef,undef) if(!$name);

    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");
    my $sql = "select id,has_vuln_info from rna_scan_type where name=\"$name\"";
    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute() || throw Error::Simple("Database Error: ".$sth->errstr);
    my ($id,$has_vuln_info) = $sth->fetchrow_array();

    return ($id,$has_vuln_info);
}

sub GetScanTypeNameById
{
    my ($id) = @_;

    if (defined $id && $id =~ /^\d+$/)
    {
        my $dbh = SF::SFDBI::connect(mysql_db => 1) || die 'Unable to connect to DB';
        my $sth = $dbh->prepare('SELECT name FROM rna_scan_type WHERE id = ?');
        $sth->execute($id) || die 'Unable to execute SQL statement';
        my $row = $sth->fetchrow_arrayref();
        $sth->finish();
        return $row->[0] if (defined $row->[0]);
    }

    return undef;
}

sub GetScanTypes
{
    # optional netmap num constraint.
    my $netmapNum = shift;

    my $scan_types = [];
    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");
    my $where = $netmapNum ? " and rsip.netmap_num = ?" : "";
    my @args  = $netmapNum ? ($netmapNum) : ();
    my $sql = "SELECT
                    name, id, has_vuln_info, rsip.netmap_num
               FROM
                    rna_scan_type rst
               INNER JOIN
                    rna_source_id_priority as rsip
                    ON rst.id = source_id
               INNER JOIN
                    domain_control_info as dci
                    ON rsip.netmap_num = dci.netmap_num
               WHERE
                    deleted = 0 " . $where;

    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute(@args) || throw Error::Simple("Database Error: ".$sth->errstr);

    while( my ($name,$id,$has_vuln_info,$netmap_num) = $sth->fetchrow_array() ){
        push( @$scan_types, { name => $name, id => $id, has_vuln_info => $has_vuln_info, netmap_num => $netmap_num} );
    }
    return $scan_types;
}

sub GetAppSourceTypes
{
    # optional netmap num constraint.
    my $netmapNum = shift;

    my $source_types = [];
    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");
    my $where = $netmapNum ? " and rsip.netmap_num = ?" : "";
    my @args  = $netmapNum ? ($netmapNum) : ();
    my $sql = "SELECT
                    name, id, rsip.netmap_num
               FROM
                    rna_source_app_str rsas
               INNER JOIN
                    rna_source_id_priority as rsip
                    ON rsas.id = source_id
               INNER JOIN
                    domain_control_info as dci
                    ON rsip.netmap_num = dci.netmap_num
               WHERE
                    deleted = 0 " . $where;

    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute(@args) || throw Error::Simple("Database Error: ".$sth->errstr);

    while( my ($name, $id, $netmap_num) = $sth->fetchrow_array() ){
        push( @$source_types, { name => $name, id => $id, netmap_num => $netmap_num } );
    }
    return $source_types;
}

sub GetSourceTypes
{
    my $source_types = [];
    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");
    my $sql = "select name, id from rna_source_type_str WHERE id != 0 ORDER BY name ASC";
    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute() || throw Error::Simple("Database Error: ".$sth->errstr);
    while( my ($name, $id) = $sth->fetchrow_array() )
    {
        push( @$source_types, { name => $name, id => $id } );
    }
    return $source_types;
}

sub GetUserIDs
{
    my $user_ids = [];
    my $dbh = SF::SFDBI::connect() || throw Error::Simple("Failed to connect to the database");
    my $sql = "SELECT u.name, u.id, p.domain_id FROM users u INNER JOIN EOPermissions p ON p.uuid=u.uuid";

    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute() || throw Error::Simple("Database Error: ".$sth->errstr);
    while( my ($name, $id, $domain_uuid) = $sth->fetchrow_array() )
    {
        push( @$user_ids, { name => $name, id => $id, domain_uuid => $domain_uuid } );
    }
    return $user_ids;
}

sub GetSourceTypeByID
{
   my $id = shift;

   if (exists($source_types->{$id}))
   {
      return $source_types->{$id};
   }
   my $dbh = SF::SFDBI::connect(mysql_db => 1) ||
      throw Error::Simple("Failed to connect to the database");
   my $sql = "select name from rna_source_type_str where id=?";
   my $sth = $dbh->prepare($sql) ||
      throw Error::Simple("Database Error: ".$dbh->errstr);
   $sth->execute($id) ||
      throw Error::Simple("Database Error: ".$sth->errstr);
    my ($name) = $sth->fetchrow_array();
    if ($name)
    {
        $source_types->{$id} = $name;
        return $name;
    }
    return "unknown";
}

sub GetSourceTypeIDByName
{
   my $name = shift;

   if (exists($source_type_names->{$name}))
   {
      return $source_type_names->{$name};
   }
   my $dbh = SF::SFDBI::connect(mysql_db => 1) ||
      throw Error::Simple("Failed to connect to the database");
   my $sql = "select id from rna_source_type_str where name=?";
   my $sth = $dbh->prepare($sql) ||
      throw Error::Simple("Database Error: ".$dbh->errstr);
   $sth->execute($name) ||
      throw Error::Simple("Database Error: ".$sth->errstr);
    my ($id) = $sth->fetchrow_array();
    if (defined($id))
    {
        $source_type_names->{$name} = $id;
        return $id;
    }
    return undef;
}

sub GetSourceAppNameByID
{
   my $id = shift;

   if (exists($app_names->{$id}))
   {
      return $app_names->{$id};
   }
   my $dbh = SF::SFDBI::connect(mysql_db => 1) ||
      throw Error::Simple("Failed to connect to the database");
   my $sql = "select name from rna_source_app_str where id=?";
   my $sth = $dbh->prepare($sql) ||
      throw Error::Simple("Database Error: ".$dbh->errstr);
   $sth->execute($id) ||
      throw Error::Simple("Database Error: ".$sth->errstr);
    my ($name) = $sth->fetchrow_array();
    if ($name)
    {
        $app_names->{$id} = $name;
        return $name;
    }
    return undef;
}

sub GetFixIDByName
{
    my ($name) = @_;

    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");

    my $sql = "SELECT fix_id FROM rna_fixes WHERE name=?";
    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);
    $sth->execute($name) || throw Error::Simple("Database Error: ".$sth->errstr);

    my ($id) = $sth->fetchrow_array();

    return ($id);
}

# This subroutine finds scan ID (in number) from scan type name (using table rna_scan_type)
sub findScanTypeID
{
    my ($scan_name, $flag, $dbh, $netmap_num) = @_;
    # NOTE: To support $dbh param, the $flag param is not optional.
    # If it is 'generic' or 0, it changes $has_vuln_info to non-default value.
    # If it is anything else (like undef) it leaves it as default value.

    if (!defined($netmap_num))
    {
        return undef;
    }

    my $table_name = "rna_scan_type";

    my $has_vuln_info = 1;  # default is 1
    $has_vuln_info = 0 if( (defined $flag && $flag eq 'generic') ||
                           (defined $flag && $flag == 0) );

    if(!defined $dbh){
        $dbh = SF::SFDBI::connect(mysql_db => 1) || die "Couldn't connect to DB";
    }

    # already an ID !
    if( $scan_name =~ /^\d+$/ )
    {
        return CheckSourceID($scan_name,$dbh,$table_name,$netmap_num);
    }

    if (exists($scan_type_ids->{$scan_name.$netmap_num}))
    {
        return $scan_type_ids->{$scan_name.$netmap_num};
    }

    my $id = CheckSourceName($scan_name, $dbh, $table_name, $netmap_num, $scan_type_ids);
    if (defined($id))
    {
        return $id;
    }

    if($scan_name && $scan_name ne "")
    {
        my $id = CreateNewSource($scan_name, $dbh, $table_name, $netmap_num, $scan_type_ids, $has_vuln_info);
        if (defined ($id))
        {
            return $id;
        }
    }
    return undef;
}

# This subroutine finds $header and removes $sub_header string from each token
# if there are any. Then build a list of tokens from the string passed in
sub parseStringList
{
    my ($str,$header,$sub_header) = @_;

    if( !($str =~ s/$header\s*//) )
    {
        AddLog("CSV Error: can not find the header: '$header' string in '$str'");
        return undef;
    }
    do
    {
        while($str =~ s/$sub_header//){}
    } if( defined($sub_header) );

    my @list = split /\s+/,$str;
    #print Dumper(\@list);
    return \@list;
}

# This subroutine removes 'CVE-' sub-string and returns CVE IDs in a list
sub parseCVEList
{
    my ($cve_str) = @_;

    return parseStringList($cve_str,'cve_ids:','CVE-');
}

# This subroutine returns BugTraq IDs in a list
sub parseBugTraqList
{
    # example: 'bugtraq_ids: 9506 9507 9508'
    my ($bug_traq_str) = @_;

    return parseStringList($bug_traq_str,'bugtraq_ids:');
}

# This subroutine preserves each scan result passed in from CSV and ready to be
# used in post processing
sub HandleCSVCmd_AddScanResult
{
    my ($hsh) = @_;

    my $mapping_item_href;
    my $generic_item_href;
    my $label;
    my ($cve_list,$bugtraq_list);

    $hsh->{params}{proto} = 6 if( $hsh->{params}{proto} &&
                                  $hsh->{params}{proto} eq 'tcp' );
    $hsh->{params}{proto} = 17 if( $hsh->{params}{proto} &&
                                   $hsh->{params}{proto} eq 'udp' );
    if( $hsh->{params}{proto} &&
        $hsh->{params}{proto} != 6 &&
        $hsh->{params}{proto} != 17 )
    {
        AddLog( "Wrong protocol $hsh->{params}{proto} entered" );
        return -1;
    }

    if( $hsh->{params}{vuln_id} && # vuln scan result case
        defined $hsh->{params}{cve_id_list} &&
        defined $hsh->{params}{bugtraq_id_list} )
    {
        $cve_list = parseCVEList($hsh->{params}{cve_id_list});
        return -1 if( !defined($cve_list) && $hsh->{params}{vuln_id} );
        $bugtraq_list = parseBugTraqList($hsh->{params}{bugtraq_id_list});
        return -1 if( !defined($bugtraq_list) && $hsh->{params}{vuln_id} );
        $mapping_item_href->{bugtraq_ids} = $bugtraq_list;
        $mapping_item_href->{cve_ids} = $cve_list;
        $mapping_item_href->{vuln_id} = $hsh->{params}{vuln_id};
        $mapping_item_href->{port} = $hsh->{params}{port};
        $mapping_item_href->{proto} = $hsh->{params}{proto};
        $mapping_item_href->{name} = $hsh->{params}{name};
        $mapping_item_href->{desc} = $hsh->{params}{desc};

        $hsh->{params}{mapping_vuln_href} = $mapping_item_href;
    }
    elsif( !$hsh->{params}{vuln_id} )  # generic scan result case
    {
        $generic_item_href->{port} = $hsh->{params}{port};
        $generic_item_href->{proto} = $hsh->{params}{proto};
        $generic_item_href->{name} = $hsh->{params}{name};
        $generic_item_href->{desc} = $hsh->{params}{desc};

        $hsh->{params}{generic_item_href} = $generic_item_href;
    }
    else
    {
        AddLog("Wrong command syntax on Vuln ID: $hsh->{params}{vuln_id}, CVE: $hsh->{params}{cve_id_list}, BugTraq: $hsh->{params}{bugtraq_id_list}");
        return -1;
    }
    return 0;
}

sub FindVulnListByIdPortProto
{
    my ($scan_id,$addr,$port,$proto,$has_host_id,$netmap_num) = @_;

    if( $proto == 6 )
    {
        $proto = 'tcp';
    }
    elsif( $proto == 17 )
    {
        $proto = 'udp';
    }
    else
    {
        $proto = '';
    }
    $port = 0 if( !defined($port) );

    my $dbh = SF::SFDBI::connect(mysql_db => 1) || throw Error::Simple("Failed to connect to the database");
    my $sql;
    my $ipHex;

    if ($has_host_id)
    {
        $sql = "SELECT id FROM rna_scan_results WHERE host_id = UNHEX(?) AND scan_type=? AND port=? AND protocol=?";
    }
    else
    {
        my $ipObj = packIP($addr);
        $ipHex = SF::QueryEngine::DataTypes::IpAddr::to_ipv6_hex($ipObj);
        $sql = "SELECT id FROM rna_scan_results left join rna_host_ip_map on rna_scan_results.host_id = rna_host_ip_map.host_id
                WHERE rna_host_ip_map.ipaddr = UNHEX(?) AND netmap_num =? AND scan_type=? AND port=? AND protocol=?";
    }
    my $sth = $dbh->prepare($sql) || throw Error::Simple("Database Error: ".$dbh->errstr);

    if ($has_host_id)
    {
        $sth->execute($addr, $scan_id, $port, $proto) || throw Error::Simple("Database Error: ".$sth->errstr);
    }
    else
    {
        $sth->execute($ipHex, $netmap_num, $scan_id, $port, $proto) || throw Error::Simple("Database Error: ".$sth->errstr);
    }

    my $vuln_list=[];
    while( my $id = $sth->fetchrow_array() )
    {
        push @{$vuln_list}, $id;
    }
    return join ',',@{$vuln_list};
}

sub ProcessDeleteScan
{
    my ($hsh, $has_host_id, $netmap_num) = @_;

    return 0 if( $hsh->{params}{mapping_vuln_href} ||
                 $hsh->{params}{generic_item_href} );

    # Example to delete all vulns/generic for port 443 and protocol TCP:
    # - DeleteScanResult,10.1.3.10,"QualysGuard", ,443,tcp
    # - DeleteScanResult,10.1.3.10,"Nmap", ,443,tcp
    # - DeleteScanResult,10.1.3.10,"Nmap"
    # - DeleteScanResult,10.1.3.10,"QualysGuard"
    my ($mapping_item_href,$generic_item_href);
    my ($id,$has_vuln_info) = GetScanTypeByName($hsh->{params}{scanner_id});
    # handle vuln results (either has vuln id or not)
    if( $hsh->{params}{id_list} ||
        ($has_vuln_info && $hsh->{params}{port} && $hsh->{params}{proto}) )
    {
        $hsh->{params}{flag} = 'delete';
        if( $hsh->{params}{id_list} )
        {
            $mapping_item_href->{id_list} = $hsh->{params}{id_list};
        }
        else
        {
            my $key = $has_host_id ? 'host_id' : 'ip_address';

            $mapping_item_href->{id_list} = FindVulnListByIdPortProto($id,
                                                                      $hsh->{params}{$key},
                                                                      $hsh->{params}{port},
                                                                      $hsh->{params}{proto},
                                                                      $has_host_id, $netmap_num);
        }
        $mapping_item_href->{port} = $hsh->{params}{port};
        $mapping_item_href->{proto} = $hsh->{params}{proto};
    }
    elsif( !$hsh->{params}{scanner_id} && $hsh->{params}{port} && $hsh->{params}{proto} )
    {
        $hsh->{params}{flag} = 'delete';
        # we should delete all scan types
        my $scan_types = GetScanTypes($netmap_num);
        my @names;
        foreach my $rec (@{$scan_types})
        {
            push @names,$rec->{name};
        }
        $hsh->{params}{scanner_id} = join ',',@names;
    }
    # delete generic results for specific port & proto
    elsif( !$hsh->{params}{id_list} && $hsh->{params}{port} &&
           $hsh->{params}{proto} )
    {
        $hsh->{params}{flag} = 'delete';
        $generic_item_href->{port} = $hsh->{params}{port};
        $generic_item_href->{proto} = $hsh->{params}{proto};
    }
    # need to delete all
    elsif( $hsh->{params}{scanner_id} && !$hsh->{params}{port} && !$hsh->{params}{proto} )
    {
        if( $has_vuln_info )
        {
            $hsh->{params}{flag} = 'delete_all_vuln';
        }
        else
        {
            $hsh->{params}{flag} = 'delete_all_generic';
        }
    }
    elsif( !$hsh->{params}{scanner_id} && !$hsh->{params}{port} && !$hsh->{params}{proto} )
    {
        $hsh->{params}{flag} = 'delete_all';
    }
    else
    {
        AddLog("Wrong command syntax on DeleteScanResult");
    }
    $hsh->{params}{mapping_vuln_href} = $mapping_item_href if($mapping_item_href);
    $hsh->{params}{generic_item_href} = $generic_item_href if($generic_item_href);
}

sub HandleCSVCmd_DeleteScanResult
{
    my ($hsh, $has_host_id, $netmap_num) = @_;

    my $label;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    # check & set to make sure the vuln id has the right port and protocol
    # - DeleteScanResult,10.1.3.1,"QualysGuard",38293
    # actually that record has (123,udp).

    $hsh->{params}{proto} = 6 if( $hsh->{params}{proto} &&
                                  $hsh->{params}{proto} eq 'tcp' );
    $hsh->{params}{proto} = 17 if( $hsh->{params}{proto} &&
                                   $hsh->{params}{proto} eq 'udp' );
    if( $hsh->{params}{proto} &&
        $hsh->{params}{proto} != 6 &&
        $hsh->{params}{proto} != 17 )
    {
        AddLog( "Wrong protocol $hsh->{params}{proto} entered" );
        return -1;
    }
    ProcessDeleteScan($hsh, $has_host_id, $netmap_num);

    return 0;
}

sub format_clean
{
    my ($data_str,$no_back_slash) = @_;

    # name and description need to be populated with a cleaned version,
    # stripped of all formatting, when inserting new scan results into
    # the rna_scan_results table (i.e. AddScanResult via Host Input)
    # this purpose of doing this is to run searching correctly

    # strip basic html tags
    $data_str =~ s/<.+?>/ /gs;

    # collapse whitespace
    $data_str =~ s/\s+/ /g;

    # trim
    $data_str =~ s/^\s+//;
    $data_str =~ s/\s+$//;

    # unescape commonly escaped html
    $data_str =~ s/&lt;/</g;
    $data_str =~ s/&gt;/>/g;
    $data_str =~ s/&amp;/&/g;
    if( $no_back_slash )
    {
        $data_str =~ s/&quot;/"/g;
    }
    else
    {
        $data_str =~ s/&quot;/\\"/g;
    }
    return $data_str;
}

# This subroutine formats the scan result data and send to SFDataCorrelator
sub _AddScanResult
{
    my ($params,$mapped_vuln_list,$generic_item_list,$flag,$netmap_num) = @_;

    my (@host_blob_list,$host_blob,@vulns,$vuln,@services,@generic_results,
        $service,$source_id);
    my $serv_href;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($ip,$scanner_id) = ($params->{ip_address},
                            $params->{scanner_id});
    my $has_vuln_info = @{$mapped_vuln_list} ? 1 : 0;

    foreach my $mapped_vuln_href (@{$mapped_vuln_list})
    {
        $vuln = undef;
        $service = undef;
        $vuln->{cve_ids} = [];
        $vuln->{bugtraq_ids} = [];
        $vuln->{desc} = $mapped_vuln_href->{desc} if(defined($mapped_vuln_href->{desc}));
        $vuln->{id} = $mapped_vuln_href->{vuln_id} if(defined($mapped_vuln_href->{vuln_id}));
        $vuln->{cve_ids} = $mapped_vuln_href->{cve_ids} if(defined($mapped_vuln_href->{cve_ids}));
        $vuln->{bugtraq_ids} = $mapped_vuln_href->{bugtraq_ids} if(defined($mapped_vuln_href->{bugtraq_ids}));
        $vuln->{port} = $mapped_vuln_href->{port} if(defined($mapped_vuln_href->{port}));
        $vuln->{proto} = $mapped_vuln_href->{proto} if(defined($mapped_vuln_href->{proto}));
        $vuln->{name} = $mapped_vuln_href->{name} if(defined($mapped_vuln_href->{name}));
        $vuln->{name_clean} = format_clean($vuln->{name}) if(defined($vuln->{name}));
        $vuln->{desc_clean} = format_clean($vuln->{desc}) if(defined($vuln->{desc}));

        push @vulns,$vuln;

        # need to add services: port/protocol here
        $service->{port} = $vuln->{port};
        $service->{proto} = $vuln->{proto};
        $service->{service_id} = undef;
        push @services,$service;
    }

    $host_blob->{proto} = undef;
    $host_blob->{vulns} = \@vulns if(scalar(@vulns));
    $host_blob->{type} = findScanTypeID($scanner_id,$has_vuln_info,undef,$netmap_num);
    $host_blob->{port} = undef;
    $host_blob->{services} = \@services if(scalar(@services));
    $host_blob->{addr} = packIP($ip);
    $host_blob->{flag} = $flag;
    my $g = getPkgVar("SF::SFDataCorrelator::UserMessage",'$SERIAL_GENERIC_SCAN_RESULT_TYPE');
    foreach my $generic_item (@{$generic_item_list})
    {
        my ($name_clean,$desc_clean) = ('','');
        $name_clean = format_clean($generic_item->{name}) if(defined($generic_item->{name}));
        $desc_clean = format_clean($generic_item->{desc}) if(defined($generic_item->{desc}));
        push(@generic_results,
        { $g =>
          [
           { unsigned_short    => $generic_item->{port} },
           { unsigned_short    => $generic_item->{proto} },
           { string => $generic_item->{name} },
           { string => $generic_item->{desc} },
           { string => $name_clean },
           { string => $desc_clean }
          ]
        });
    }
    $host_blob->{generic_results} = \@generic_results;

    #warn "host blob list: ".Dumper($host_blob);

    my $data = SF::SFDataCorrelator::UserMessage::BuildAddScanResultEvent(0,$host_blob, $netmap_num);
    my $rval;
    if ( ($rval = SF::SFDataCorrelator::UserMessage::DoUserMessage($data)) != 0 )
    {
        AddLog("Failed to send UserMessage");
        return $rval;
    }
    return 0;
}

# Host Input API: AddScanResult() to build scan result data and send to SFD to process.
# It also support HA
sub AddScanResult
{
    my ($params,$mapped_vuln_list,$generic_item_list,$flag,$netmap_num) = @_;

    my $rval;

    # tell the other side to do this as well...
    if( SF::COOP::enabled() && $do_sync )
    {
        # Save the scanner id and replace it back in params after adding the transaction
        my $scanner_id = $params->{scanner_id};

        # If it's an ID, get the corresponding name,
        # because the HA peer uses a different ID number range.
        if ($params->{scanner_id} =~ /^\d+$/)
        {
            $params->{scanner_id} = GetScanTypeNameById($params->{scanner_id});
        }
        SF::COOP::add_ha_transaction( \&_AddScanResult, { args => [ $params,$mapped_vuln_list,$generic_item_list,$flag, $netmap_num ] }, "Add Scan Result", 10 );

        $params->{scanner_id} = $scanner_id;
    }
    if( SF::Types::is_valid('ip',$params->{ip_address}, {ipv4or6 => 1}) )
    {
        $rval = _AddScanResult($params,$mapped_vuln_list,$generic_item_list,$flag,$netmap_num);
    }
    else
    {
        AddLog("Failed to recognize IP address: $params->{ip_address}");
        return -1;
    }
    return $rval;
}

# This subroutine format the scan result data and send to SFD
sub _DeleteScanResult
{
    my ($params,$mapped_vuln_list,$generic_item_list,$flag,$netmap_num,$has_host_id) = @_;

    my (@host_blob_list,$host_blob,@vulns,$vuln,@services,$service,@generic_results,
        $source_id);
    my $serv_href;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my $address = $has_host_id ? $params->{host_id} : $params->{ip_address};
    my $scanner_id = $params->{scanner_id};
    my $has_vuln_info = @{$mapped_vuln_list} ? 1 : 0;

    foreach my $mapped_vuln_href (@{$mapped_vuln_list})
    {
        if(defined($mapped_vuln_href->{id_list}))
        {
            foreach my $item (split ',',$mapped_vuln_href->{id_list})
            {
                $vuln = undef;
                $service = undef;
                $vuln->{cve_ids} = [];
                $vuln->{bugtraq_ids} = [];
                $vuln->{id} = $item;
                $vuln->{port} = $mapped_vuln_href->{port} if(defined($mapped_vuln_href->{port}));
                $vuln->{proto} = $mapped_vuln_href->{proto} if(defined($mapped_vuln_href->{proto}));
                push @vulns,$vuln;
                $service->{port} = $vuln->{port} if($vuln->{port});
                $service->{proto} = $vuln->{proto} if($vuln->{proto});
                #$service->{service_id} = undef;
                push @services,$service;
            }
        }
    }
    my $g = getPkgVar("SF::SFDataCorrelator::UserMessage",'$SERIAL_GENERIC_SCAN_RESULT_TYPE');
    foreach my $generic_item (@{$generic_item_list})
    {
        my ($name_clean,$desc_clean) = ('','');
        $name_clean = format_clean($generic_item->{name}) if(defined($generic_item->{name}));
        $desc_clean = format_clean($generic_item->{desc}) if(defined($generic_item->{desc}));
        push(@generic_results,
        { $g =>
          [
           { unsigned_short    => $generic_item->{port} },
           { unsigned_short    => $generic_item->{proto} },
           { string => $generic_item->{name} },
           { string => $generic_item->{desc} },
           { string => $name_clean },
           { string => $desc_clean }
          ]
        });
    }
    $host_blob->{generic_results} = \@generic_results if(scalar(@generic_results));
    $host_blob->{proto} = undef;
    $host_blob->{vulns} = \@vulns if(scalar(@vulns));
    $host_blob->{type} = findScanTypeID($scanner_id,$has_vuln_info,undef,$netmap_num) if($scanner_id);
    $host_blob->{port} = undef;
    $host_blob->{services} = \@services if(scalar @services);

    $host_blob->{addr} = $has_host_id ? $address: packIP($address);
    $host_blob->{flag} = $flag;

    #warn "host blob list: ".Dumper($host_blob);

    my $data = SF::SFDataCorrelator::UserMessage::BuildAddScanResultEvent(0, $host_blob, $netmap_num, $has_host_id);
    my $rval;
    if ( ($rval = SF::SFDataCorrelator::UserMessage::DoUserMessage($data)) != 0 )
    {
        AddLog("Failed to send UserMessage");
        return $rval;
    }
    return 0;
}

# Host Input API: AddScanResult() to build scan result data and send to SFD to process.
# It also support HA
sub DeleteScanResult
{
    my ($params,$mapped_vuln_list,$generic_item_list,$flag, $netmap_num, $has_host_id) = @_;

    my $rval;

    # tell the other side to do this as well...
    if( SF::COOP::enabled() && $do_sync )
    {
        if ($has_host_id)
        {
            my $host_ip = SF::RNA::Hosts::getHostIPs($params->{host_id});
            $params->{ip_address} = $host_ip->[0];
        }

        # Save the scanner id and replace it back in params after adding the transaction
        my $scanner_id = $params->{scanner_id};

        # If it's an ID, get the corresponding name,
        # because the HA peer uses a different ID number range.
        if ($params->{scanner_id} =~ /^\d+$/)
        {
            $params->{scanner_id} = GetScanTypeNameById($params->{scanner_id});
        }

        SF::COOP::add_ha_transaction( \&_DeleteScanResult, { args => [ $params,$mapped_vuln_list,$generic_item_list,$flag,$netmap_num,0 ] }, "Delete Scan Result", 10 );

        $params->{scanner_id} = $scanner_id;
    }
    if (!defined($has_host_id))
    {
        if( !SF::Types::is_valid('ip',$params->{ip_address}, {ipv4or6 => 1}) )
        {
            AddLog("Failed to recognize IP address: $params->{ip_address}");
            return -1;
        }
    }

    $rval = _DeleteScanResult($params,$mapped_vuln_list,$generic_item_list,$flag,$netmap_num,$has_host_id);
    return $rval;
}

sub InsertScanCmd
{
    my ($id,$hsh,$ScanResult_Cmds) = @_;

    my @array;
    if( ref $ScanResult_Cmds->{$id} eq 'ARRAY' )
    {
        push @{$ScanResult_Cmds->{$id}},$hsh;
    }
    else
    {
        $ScanResult_Cmds->{$id} = \@array;
        push @array,$hsh;
    }
    return $ScanResult_Cmds;
}

sub PostProcessingDeleteScanResult
{
    my ($hsh, $DelScanResult_Cmds, $has_host_id, $netmap_num) = @_;

    my $flag = $hsh->{params}{flag} ? $hsh->{params}{flag} : '';
    my $scanners = $hsh->{params}{scanner_id} ? $hsh->{params}{scanner_id} : '';
    my $key = $has_host_id ? 'host_id' : 'ip_address';
    # this is the delete all case
    if( $scanners eq '' && $hsh->{params}{flag} )
    {
        my $id = '_'.$hsh->{params}{$key}.'_'.$flag;
        $DelScanResult_Cmds = InsertScanCmd($id,$hsh,$DelScanResult_Cmds);
        return;
    }
    my @scanner_names = split ',',$scanners;
    foreach my $scanner_id (@scanner_names)
    {
        my $id = $scanner_id.'_'.$hsh->{params}{$key}.'_'.$flag;
        my $hsh_rec = dclone($hsh);
        $hsh_rec->{params}{scanner_id} = $scanner_id;
        ProcessDeleteScan($hsh_rec, $has_host_id, $netmap_num);
        $DelScanResult_Cmds = InsertScanCmd($id,$hsh_rec,$DelScanResult_Cmds);
    }
    return $DelScanResult_Cmds;
}

# For CSV file case, we need to handle all AddScanResult commands no matter if 'ScanFlush'
# exists or not
# Basically, we save all the results based on socket (in memory).
# When we see 'ScanFlush', we call AddScanResult() to send them to SFD to process.
sub PostProcessingCmds
{
    my ($cmds,$sock) = @_;

    my $source_href;
    my ($AddScanResult_Cmds,$DelScanResult_Cmds);

    my $netmap_num = $postprocessing_netmap_num;

    if( defined($sock) )
    {
        $AddScanResult_Cmds = $Sock_AddScanResult->{$sock} if( defined($Sock_AddScanResult->{$sock}) );
        $DelScanResult_Cmds = $Sock_DelScanResult->{$sock} if( defined($Sock_DelScanResult->{$sock}) );
    }
    foreach my $hsh (@$cmds)
    {
        next if( $hsh->{cmd} ne 'AddScanResult' &&
                 $hsh->{cmd} ne 'DeleteScanResult' &&
                 $hsh->{cmd} ne 'ScanUpdate' &&
                 $hsh->{cmd} ne 'ScanFlush' );
        # for each unique 'key' (combination of scanner_id and ip_address)
        # we build a hash reference with an array as the value. Each array has a list
        # of $hsh (multiple commands of the same key)
        # Example of one key: 'Qualys_10.4.10.73'
        if( $hsh->{cmd} eq 'AddScanResult')
        {
            my $scanner_id = $hsh->{params}{scanner_id} ? $hsh->{params}{scanner_id} : '';
            my $id = $scanner_id.'_'.$hsh->{params}{ip_address};
            $AddScanResult_Cmds = InsertScanCmd($id,$hsh,$AddScanResult_Cmds);
        }
        if( $hsh->{cmd} eq 'DeleteScanResult')
        {
            $DelScanResult_Cmds = PostProcessingDeleteScanResult($hsh, $DelScanResult_Cmds, 0, $netmap_num);
        }
        if( $hsh->{cmd} eq 'ScanFlush' )
        {
            runScanResultCommands($AddScanResult_Cmds,'flush');
            $AddScanResult_Cmds = undef; # @add_array = ();
            CleanSocketScanResult($sock,'add');
        }
        if( $hsh->{cmd} eq 'ScanUpdate' )
        {
            runScanResultCommands($DelScanResult_Cmds,'delete');
            runScanResultCommands($AddScanResult_Cmds,'update');
            $AddScanResult_Cmds = undef; # @add_array = ();
            $DelScanResult_Cmds = undef; # @del_array = ();
            CleanSocketScanResult($sock,'add');
            CleanSocketScanResult($sock,'del');
        }
    }
    $Sock_AddScanResult->{$sock} = $AddScanResult_Cmds if(defined($sock) &&
                                                          defined($AddScanResult_Cmds));
    $Sock_DelScanResult->{$sock} = $DelScanResult_Cmds if(defined($sock) &&
                                                          defined($DelScanResult_Cmds));
    #print "Sock_AddScanResult: ".Dumper($Sock_AddScanResult);

    # Now if this is CSV file case, we need to handle rest of commands
    # before the process exit, we will assume this is doing 'ScanUpdate'
    if( !defined($sock) )
    {
        runScanResultCommands($DelScanResult_Cmds,'delete');
        runScanResultCommands($AddScanResult_Cmds,'update');
    }
}

sub findCmdList
{
    my ($list,$sub_str) = @_;

    my $ret_list;
    foreach my $item (@{$list})
    {
        push @{$ret_list},$item if( $item =~ /$sub_str$/ );
    }
    return $ret_list;
}

sub runSubScanResultCommands
{
    my ($flag,$array, $netmap_num, $has_host_id) = @_;

    my (@mapping_vuln_list,@generic_item_list);
    foreach my $cmd (@{$array})
    {
        push @mapping_vuln_list,$cmd->{params}{mapping_vuln_href} if($cmd->{params}{mapping_vuln_href});
        push @generic_item_list,$cmd->{params}{generic_item_href} if($cmd->{params}{generic_item_href});
    }
    my $rval = 0;

    if( $flag == 0 || $flag == $update_flag )
    {
        $rval = AddScanResult({ ip_address => @$array[0]->{params}{ip_address},
                                scanner_id => @$array[0]->{params}{scanner_id} },
                              \@mapping_vuln_list,
                              \@generic_item_list,$flag,
                              $netmap_num);
    }
    elsif( $flag == $delete_flag || $flag == $delete_all_vuln_flag ||
           $flag == $delete_all_generic_flag || $flag == $delete_all_flag)
    {
        $rval = DeleteScanResult(@$array[0]->{params},
                                 \@mapping_vuln_list,
                                 \@generic_item_list,$flag,
                                 $netmap_num, $has_host_id);
    }
    $result_string .= formatScanResult($rval,$array);
}

# This subroutine run all the AddScanResult() when we see 'ScanFlush' or 'ScanUpdate'
sub runScanResultCommands
{
    my ($cmds,$action, $netmap_num, $has_host_id) = @_;

    if (!defined($netmap_num))
    {
        $netmap_num = $postprocessing_netmap_num;
    }
    #print Dumper($cmds);
    my @list = keys %{$cmds};

    if( $action eq 'delete' )
    {
        # Run 'delete' first
        my $key_list = findCmdList(\@list,'_delete_all');
        foreach my $key (@{$key_list})
        {
            runSubScanResultCommands($delete_all_flag,$cmds->{$key}, $netmap_num, $has_host_id);
        }
        $key_list = findCmdList(\@list,'_delete_all_vuln');
        foreach my $key (@{$key_list})
        {
            runSubScanResultCommands($delete_all_vuln_flag,$cmds->{$key}, $netmap_num, $has_host_id);
        }
        $key_list = findCmdList(\@list,'_delete_all_generic');
        foreach my $key (@{$key_list})
        {
            runSubScanResultCommands($delete_all_generic_flag,$cmds->{$key}, $netmap_num, $has_host_id);
        }
        $key_list = findCmdList(\@list,'_delete');
        foreach my $key (@{$key_list})
        {
            runSubScanResultCommands($delete_flag,$cmds->{$key}, $netmap_num, $has_host_id);
        }
    }
    elsif( $action eq 'flush' )  # only 'AddScanResult'
    {
        # Then run 'add without update'
        foreach my $key (@list)
        {
            runSubScanResultCommands(0,$cmds->{$key}, $netmap_num, $has_host_id);
        }
    }
    elsif( $action eq 'update' )  # 'AddScanResult' & 'DeleteScanResult'
    {
        # Run 'add with update' last
        foreach my $key (@list)
        {
            runSubScanResultCommands($update_flag,$cmds->{$key}, $netmap_num, $has_host_id);
        }
    }
}

# This subroutine returns the specific command in CSV format if the return code
# passed-in is non-zero (failure case)
sub formatScanResult
{
    my ($rval,$array) = @_;

    if($rval != 0)
    {
        return "Failure to Run Scan API: \n".formatScanCmds($array)."\n\n";
    }
    return "";
}

# This subroutine formats scan results into simple command, IP and count of vulnerability.
# This is used in formatting result string and send back to remote client when command
# fails
sub formatScanCmds
{
    my ($array) = @_;

    my ($return_str,$ip_addr,$command,$count);
    if( ref $array eq 'ARRAY' )
    {
        $count = scalar @{$array};
        # $array will always have the same IP and command, so just pick the first one
        $command = $array->[0]->{cmd};
        $ip_addr = $array->[0]->{params}{ip_address};
        $return_str .= "Command: $command, IP: $ip_addr, vuln_count = $count\n";
    }
    return $return_str;
}

# This usbroutine formats CVE or BugTraq ID list into CSV format
sub formatStrIDCmd
{
    my ($head,$id_array,$sub_head) = @_;

    my @str_list;
    $sub_head = "" if( !defined($sub_head) );
    foreach my $item (@{$id_array})
    {
        push @str_list,$sub_head.$item;
    }

    return $head.join ' ',@str_list;
}

# This subroutine records error and build result string for remote client case
sub AddLog
{
    my ($str,$layer) = @_;

    $layer = 0 if(!defined($layer));
    my ($package,$file,$line) = caller($layer);
    $str .= " [$file,$line]\n";
    warn $str;
    $result_string .= $str;
}

# This subroutine deletes client socket and remove it from the select
sub socketCleanUp
{
    my ($sock) = @_;

    return if( !defined($sock) );

    # run the remaining data stored in socket
    # assume they are running 'ScanUpdate'
    my $AddScanResult_Cmds = $Sock_AddScanResult->{$sock};
    my $DelScanResult_Cmds = $Sock_DelScanResult->{$sock};
    runScanResultCommands($DelScanResult_Cmds,'delete') if(defined($DelScanResult_Cmds));
    runScanResultCommands($AddScanResult_Cmds,'update') if(defined($AddScanResult_Cmds));

    # clean up scan result about this socket
    CleanSocketScanResult($sock,'add');
    CleanSocketScanResult($sock,'del');
}

# This subroutine cleans up saved scan result data based on each managed client
sub CleanSocketScanResult
{
    my ($sock,$action) = @_;

    delete $Sock_AddScanResult->{$sock} if(defined($sock) && $action eq 'add');
    delete $Sock_DelScanResult->{$sock} if(defined($sock) && $action eq 'del');
    #warn "Scan Result Socket: '$sock' deleted";
}

sub create_client
{
    my($hostname,$password) = @_;

    my $error = undef;

    if ($hostname)
    {
        my $domain_uuid = SF::MultiTenancy::getCurrentDomain();

        if (SF::Types::is_valid("hostnameIp", $hostname,{ipv4or6=>1}))
        {
            if(! -d $DEFAULT_LOCATION_RELOC)
            {
                my $rval;
                try
                {
                    $rval = SF::System::Privileged::mkdir(dir => $DEFAULT_LOCATION);
                }
                catch Error::SFSystem with
                {
                    my $E = shift;
                    warn "$E->stringify\n";
                    $rval->{stdout}="";
                    $error = SF::i18n::get_format_pm_msg("error_create_cert_for_1", "main", (1, $hostname));
                };
            }

            use Cwd 'chdir';
            chdir $DEFAULT_LOCATION_RELOC;
            if($password)
            {
                my $rval;
                try
                {
                    $rval = SF::System::Privileged::add_hostinputd_client(hostname => $hostname, passwd => $password, domain_uuid => $domain_uuid);
                }
                catch Error::SFSystem with
                {
                    my $E = shift;
                    warn "$E->stringify\n";
                    $rval->{stdout}="";
                    $error = SF::i18n::get_format_pm_msg("error_create_cert_for_1", "main", (1, $hostname));
                };
            }
            else
            {
                my $rval;
                try
                {
                    $rval = SF::System::Privileged::add_hostinputd_client(hostname => $hostname, domain_uuid => $domain_uuid);
                }
                catch Error::SFSystem with
                {
                    my $E = shift;
                    warn "$E->stringify\n";
                    $rval->{stdout}="";
                    $error = SF::i18n::get_format_pm_msg("error_create_cert_for_1", "main", (1, $hostname));
                };
            }
        }
        else
        {
            $error = SF::i18n::get_pm_msg("invalid_hostname_specified", "main");
        }
    }
    else
    {
        $error = SF::i18n::get_pm_msg("no_hostname_specified", "main");
    }
    return $error;
}

my $PM_STOPBYID = getPkgVar("SF::PM::Control", '$PMStopByID');

sub delete_client
{
    my ($hostname, $location, $domain_uuid, $opt) = @_;

    my $rval;
    try
    {
        warn "HostInput: about to shred: $location\n";
        $rval = SF::System::Privileged::shred(filename => $location, option => "fuz");
    }
    catch Error::SFSystem with
    {
        my $E = shift;
        $rval->{stdout}="";
    };

    try
    {
        my $domain_uuid = SF::MultiTenancy::getCurrentDomain();
        $rval = SF::System::Privileged::delete_hostinputd_client(hostname => $hostname, domain_uuid => $domain_uuid);
    }
    catch Error::SFSystem with
    {
        my $E = shift;
        warn "$E->stringify\n";
        $rval->{stdout}="";
    };

    if($opt && $opt->{restart})
    {

        $hostname = SF::PM::Control::MakeConnection() || return;
        SF::PM::Control::DoControlCommand($hostname,
                                        $PM_STOPBYID,
                                        "HostInput_Daemon");
        SF::PM::Control::CloseConnection($hostname);
    }
}

sub get_clients
{
    my $allDomains = shift;
    $allDomains = $allDomains // 0;

    my $manager = undef;
    if (SF::Global::isMC())
    {
        my $role = 5;
        my $peer = SF::PeerManager::getActiveByRole($role);
        if (defined($peer) && exists($peer->[0]{uuid}))
        {
            $manager = $peer->[0]{uuid};
        }
    }
    my $dbh = SF::SFDBI::connect(mysql_db => 1) || die "Can't connect: $DBI::errstr\n";
    my $sql = "SELECT hostname, cert_serial_number from ssl_peer WHERE service='hostinputd' AND role='client' ";
    if(!$allDomains){
        my $domain_uuid = SF::MultiTenancy::getCurrentDomain();
        $sql .= " and domain_uuid=uuid_atob('$domain_uuid')";
    }
    my $sth = $dbh->prepare($sql) || die "Can't prepare: $DBI::errstr\n";
    $sth->execute() || die "Can't execute: $DBI::errstr\n";
    my @clients = ();
    while (my @row = $sth->fetchrow_array())
    {
        next if !$row[0];
        next if (defined($manager) && $manager eq $row[0]);

        my $hostname   = $row[0];
        my $serial_num = $row[1];
        my $name       = "$hostname".'_'."$serial_num.pkcs12";
        my $location   = "$DEFAULT_LOCATION_RELOC/$name";

        if ( ! (-e $location) ) { $location = undef; }

        push(@clients, {name => $hostname, serial_num => $serial_num, location => $location} );
    }

    $sth->finish();

    return \@clients;
}

my $HID_ENABLE_FILE = "/etc/sf/keys/sfhostinputd.pkcs12";
my $HID_ENABLE_FILE_RELOC = SF::Reloc::RelocateFilename($HID_ENABLE_FILE);

sub actOnHIDaemon
{
    my ($create_flag,$error) = @_;

    try {
        my $hi_clients = SF::SFDataCorrelator::HostInput::get_clients(1);
        my $hi_client_count = scalar @{$hi_clients};

        if( $hi_client_count == 0 )  # no more HI clients
        {
            # Stop HIDaemon
            if(-e $HID_ENABLE_FILE_RELOC)
            {

                SF::System::Privileged::move(source => "$HID_ENABLE_FILE", dest => "$HID_ENABLE_FILE.disabled");
            }
            SF::PeerManager::ConfigFiles::update_iptables_rule(
                {
                    rule => "\n",
                    "ipv4" => 1,
                    open_tag  => '#start Host Input Daemon Port BLOCK',
                    close_tag => '#stop Host Input Daemon Port BLOCK',
                }
            );
            SF::PeerManager::ConfigFiles::update_iptables_rule(
                {
                    rule => "\n",
                    "ipv6" => 1,
                    open_tag  => '#start Host Input Daemon Port BLOCK',
                    close_tag => '#stop Host Input Daemon Port BLOCK',
                }
            );
            my $client = SF::PM::Control::MakeConnection() || return "No Connection";
            SF::PM::Control::DoControlCommand($client, $PM_STOPBYID, "HostInput_Daemon");
            SF::PM::Control::CloseConnection($client);

        }
        elsif( $hi_client_count == 1 && !defined( $error ) && $create_flag )  # just created the first HI client
        {
            # Start HIDaemon
            if(-e "$HID_ENABLE_FILE_RELOC.disabled")
            {
                SF::System::Privileged::move(source => "$HID_ENABLE_FILE.disabled", dest => "$HID_ENABLE_FILE");
            }
            my $MNG_IF_NAME = SF::Util::get_management_interface() || "";

            my $MNG_IF_NAMES = [$MNG_IF_NAME];

            my $if_config = SF::NetworkConf::loadInterfacesConfig();
            if($if_config)
            {
                $MNG_IF_NAMES = [];
                foreach my $key (keys %{ $if_config->{interfaces} })
                {
                    if(!$if_config->{interfaces}{$key})
                    {
                        next;
                    }
                    else
                    {
                        push @{$MNG_IF_NAMES},$key;
                    }
                }
            }
            my $rules = "";
            foreach $MNG_IF_NAME (@{$MNG_IF_NAMES})
            {
                $rules .= "-A INPUT -i $MNG_IF_NAME -p tcp -m tcp --dport 8307 -j ACCEPT\n";
            }

            SF::PeerManager::ConfigFiles::update_iptables_rule(
                {
                    rule => $rules,
                    "ipv4" => 1,
                    open_tag  => '#start Host Input Daemon Port BLOCK',
                    close_tag => '#stop Host Input Daemon Port BLOCK',
                }
            );
            SF::PeerManager::ConfigFiles::update_iptables_rule(
                {
                    rule => $rules,
                    "ipv6" => 1,
                    open_tag  => '#start Host Input Daemon Port BLOCK',
                    close_tag => '#stop Host Input Daemon Port BLOCK',
                }
            );
            my $client = SF::PM::Control::MakeConnection() || return "No Connection";
            SF::PM::Control::DoControlCommand($client, $PM_STOPBYID, "HostInput_Daemon");
            SF::PM::Control::CloseConnection($client);
        }

    }  catch Error with
    {
        my $E = shift;
        warn "ERR:($E)";
    };

}

sub DeleteHostIOCTag
{
    my ($source_type, $uid, $addr_string, $ioc_id, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my $data = SF::SFDataCorrelator::UserMessage::BuildHostIOCDeleteEvent($source_type, $uid, $address_list, $ioc_id, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage($data);
    if($return != 0)
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage(SF::SFDataCorrelator::UserMessage::BuildHostIOCDeleteEvent($source_type, $uid, eval(\"$addr_list_dumped\"), $ioc_id, $netmap_num, 0));
EOF
        SF::COOP::add_transaction($thunk);
    }

    return $return;
}

sub DeleteAllHostIOC
{
    my ($source_type, $uid, $addr_string, $netmap_num) = @_;
    return DeleteHostIOCTag($source_type, $uid, $addr_string, 0, $netmap_num);
}

# This function is used by the automation team for product testing.
# If you change the arguments, output, or functionality of this function
# please open a bug:
#
# Product: Automation
# Component: ATF:Framework
# Subject should start with: SF_API Changes
#
sub MarkHostIOCTagEnabled
{
    my ($source_type, $uid, $addr_string, $ioc_id, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my $data = SF::SFDataCorrelator::UserMessage::BuildHostIOCEnableEvent($source_type, $uid, $address_list, $ioc_id, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage($data);
    if($return != 0)
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage(SF::SFDataCorrelator::UserMessage::BuildHostIOCEnableEvent($source_type, $uid, eval(\"$addr_list_dumped\"), $ioc_id, $netmap_num, 0));
EOF
        SF::COOP::add_transaction($thunk);
    }

    return $return;
}

# This function is used by the automation team for product testing.
# If you change the arguments, output, or functionality of this function
# please open a bug:
#
# Product: Automation
# Component: ATF:Framework
# Subject should start with: SF_API Changes
#
sub MarkHostIOCTagDisabled
{
    my ($source_type, $uid, $addr_string, $ioc_id, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentLeafDomain();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my ($address_list, $has_host_id, $ip_addr_list) = convertAddressOrUUID($addr_string);

    my $data = SF::SFDataCorrelator::UserMessage::BuildHostIOCDisableEvent($source_type, $uid, $address_list, $ioc_id, $netmap_num, $has_host_id);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage($data);
    if($return != 0)
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled() && $do_sync)
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $addr_list_dumped = ($has_host_id) ? Data::Dumper::Dumper($ip_addr_list) : Data::Dumper::Dumper( $address_list );
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage(SF::SFDataCorrelator::UserMessage::BuildHostIOCDisableEvent($source_type, $uid, eval(\"$addr_list_dumped\"), $ioc_id, $netmap_num, 0));
EOF
        SF::COOP::add_transaction($thunk);
    }

    return $return;
}

sub DeleteUserIOCTag
{
    my ($user_id, $ioc_id, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentNetmapNum();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my $uid = 0;
    my $source_type = getPkgVar('SF::SFDataCorrelator::UserMessage', 'SOURCE_TYPE_USER');
    my $data = SF::SFDataCorrelator::UserMessage::BuildUserIOCDeleteEvent($source_type, $uid, $user_id, $ioc_id, $netmap_num);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage($data);
    if($return != 0)
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled())
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage(SF::SFDataCorrelator::UserMessage::BuildUserIOCDeleteEvent($source_type, $uid, $user_id, $ioc_id, $netmap_num));
EOF
        SF::COOP::add_transaction($thunk);
    }

    return $return;
}

sub DeleteAllUserIOC
{
    my ($user_id, $netmap_num) = @_;

    return DeleteUserIOCTag($user_id, 0, $netmap_num);
}

sub MarkUserIOCTagEnabled
{
    my ($user_id, $ioc_id, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentNetmapNum();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my $uid = 0;
    my $source_type = getPkgVar('SF::SFDataCorrelator::UserMessage', 'SOURCE_TYPE_USER');
    my $data = SF::SFDataCorrelator::UserMessage::BuildUserIOCEnableEvent($source_type, $uid, $user_id, $ioc_id, $netmap_num);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage($data);
    if($return != 0)
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled())
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage(SF::SFDataCorrelator::UserMessage::BuildUserIOCEnableEvent($source_type, $uid, $user_id, $ioc_id, $netmap_num));
EOF
        SF::COOP::add_transaction($thunk);
    }

    return $return;
}

sub MarkUserIOCTagDisabled
{
    my ($user_id, $ioc_id, $netmap_num) = @_;

    if (!defined($netmap_num) || $netmap_num == 0 )
    {
        $netmap_num = getCurrentNetmapNum();
        if (!defined($netmap_num))
        {
            return -1;
        }
    }

    my $uid = 0;
    my $source_type = getPkgVar('SF::SFDataCorrelator::UserMessage', 'SOURCE_TYPE_USER');
    my $data = SF::SFDataCorrelator::UserMessage::BuildUserIOCDisableEvent($source_type, $uid, $user_id, $ioc_id, $netmap_num);
    my $return = SF::SFDataCorrelator::UserMessage::DoUserMessage($data);
    if($return != 0)
    {
        AddLog("Failed to send UserMessage");
    }

    if (SF::COOP::enabled())
    {
        require Data::Dumper;
        local $Data::Dumper::Terse=1;
        my $thunk = <<"EOF";
use SF::SFDataCorrelator::UserMessage;
SF::SFDataCorrelator::UserMessage::DoUserMessage(SF::SFDataCorrelator::UserMessage::BuildUserIOCDisableEvent($source_type, $uid, $user_id, $ioc_id, $netmap_num));
EOF
        SF::COOP::add_transaction($thunk);
    }

    return $return;
}

1;

