import argparse
import frida
import os
import sys

from dwarf_debugger.lib import utils
from dwarf_debugger.lib.plugin_manager import PluginManager


plugin_manager = PluginManager(None)


class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)


def initialize_arg_parser():
    parser = ArgParser()
    parser.add_argument(
        "-t",
        "--target",
        default='local',
        type=str,
        help="SessionType - android, ios, local, remote - default: local")
    parser.add_argument("-dev", "--device", help="DeviceSerial adb devices, optional - for multiple device attached")

    parser.add_argument('any', nargs='?', default='', help='path/pid/package')
    parser.add_argument('args', nargs='*', default=[''], help='arguments')
    return parser


def attach(args, device, user_script):
    """ Attach to pid
    """

    _process = None
    was_error = False
    error_msg = ''
    pid = args.pid

    # for commandline arg
    if isinstance(pid, str):
        try:
            process = device.get_process(pid)
            pid = [process.pid, process.name]
        except frida.ProcessNotFoundError as error:
            raise Exception('Frida Error: ' + str(error))

    if isinstance(pid, list):
        pid = pid[0]

    if not isinstance(pid, int):
        raise Exception('Error pid!=int')

    try:
        _process = device.attach(pid)
        _pid = pid
    except frida.ProcessNotFoundError:
        error_msg = 'Process not found (ProcessNotFoundError)'
        was_error = True
    except frida.ProcessNotRespondingError:
        error_msg = 'Process not responding (ProcessNotRespondingError)'
        was_error = True
    except frida.TimedOutError:
        error_msg = 'Frida timeout (TimedOutError)'
        was_error = True
    except frida.ServerNotRunningError:
        error_msg = 'Frida not running (ServerNotRunningError)'
        was_error = True
    except frida.TransportError:
        error_msg = 'Frida timeout was reached (TransportError)'
        was_error = True
    # keep for debug
    except Exception as error:  # pylint: disable=broad-except
        error_msg = error
        was_error = True

    if was_error:
        raise Exception(error_msg)

    load_script(args, _process, user_script)


def spawn(args, device, user_script):
    _process = None
    _pid = 0
    package = args.any
    package_args = args.args

    if args is None:
        args = []

    try:
        if package == '-':
            args.pid = os.getpid()
            attach(args, device, user_script)
        else:
            if device.type == 'local':
                _pid = device.spawn([package] + package_args)
            else:
                # args not supported in remote targets
                _pid = device.spawn(package)
            _package = package
            _process = device.attach(_pid)
            # _process.on('detached', self._on_detached)
            _spawned = True
    except Exception as e:
        raise Exception('Frida Error: ' + str(e))

    load_script(args, _process, user_script, spawned=True)
    device.resume(_pid)
    return _pid


def on_message(message, payload):
    for plugin in plugin_manager.plugins:
        plugin_instance = plugin_manager.plugins[plugin]
        try:
            plugin_instance.on_frida_message(message, payload)
        except:
            pass


def load_script(args, proc, user_script, spawned=False):
    try:
        if not os.path.exists(utils.resource_path('lib/core.js')):
            print('core.js not found!')
            exit(0)

        with open(utils.resource_path('lib/core.js'), 'r') as core_script:
            script_content = core_script.read()

        _script = proc.create_script(script_content, runtime='v8')
        _script.on('message', on_message)
        # _script.on('destroyed', _on_script_destroyed)
        _script.load()

        try:
            is_debug = args.debug_script
        except:
            is_debug = False
        try:
            break_start = args.break_start
        except:
            break_start = False
        # this break_at_start have same behavior from args or from the checkbox i added
        _script.exports.init(break_start, is_debug, spawned)

        plugin_manager.reload_plugins()

        for plugin in plugin_manager.plugins:
            plugin_instance = plugin_manager.plugins[plugin]
            try:
                _script.exports.api(0, 'evaluateFunction', [plugin_instance.__get_agent__()])
                plugin_instance.set_script(_script)
            except Exception as e:
                pass

        if user_script is not None:
            _script.exports.api(0, 'evaluateFunction', [user_script])
        return 0
    except frida.ProcessNotFoundError:
        error_msg = 'Process not found (ProcessNotFoundError)'
        was_error = True
    except frida.ProcessNotRespondingError:
        error_msg = 'Process not responding (ProcessNotRespondingError)'
        was_error = True
    except frida.TimedOutError:
        error_msg = 'Frida timeout (TimedOutError)'
        was_error = True
    except frida.ServerNotRunningError:
        error_msg = 'Frida not running (ServerNotRunningError)'
        was_error = True
    except frida.TransportError:
        error_msg = 'Frida timeout was reached (TransportError)'
        was_error = True

    if was_error:
        utils.show_message_box(error_msg)
    return 1


def attach_spawn_target(args, user_script=None):
    if not args.target and not args.device:
        print('missing session type. use -t local|android|ios|remote to define the session type'
              ' or specify a device id with --device')
        exit(0)

    if args.any is None or args.any == '':
        print('missing file or package name to attach')
        exit(0)

    device = None
    try:
        if args.device:
            device = frida.get_device(id=args.device)
        else:
            session_type = args.target.lower()
            if session_type == 'local':
                device = frida.get_local_device()
            elif session_type == 'android' or session_type == 'ios':
                device = frida.get_usb_device(5)
            elif session_type == 'remote':
                device = frida.get_remote_device()
    except Exception as e:
        print('failed to get frida device')
        print(e)

    if device is not None:
        try:
            # parse target as pid
            args.pid = int(args.any)
        except ValueError:
            args.pid = 0

        if args.pid > 0:
            print('* Trying to attach to {0}'.format(args.pid))
            try:
                attach(args, device)
                print('* Dwarf attached to {0}'.format(args.pid))
            except Exception as e:  # pylint: disable=broad-except
                print('-failed-')
                print('Reason: ' + str(e))
                print('Help: you can use -sp to force spawn')
                exit(0)
        else:
            print('* Trying to spawn {0}'.format(args.any))
            try:
                _pid = spawn(args, device, user_script)
                print('* Dwarf attached to {0}'.format(_pid))
            except Exception as e:  # pylint: disable=broad-except
                print('-failed-')
                print('Reason: ' + str(e))
                exit(0)

        sys.stdin.read()
