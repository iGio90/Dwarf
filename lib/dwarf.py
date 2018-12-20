import json


class Dwarf(object):
    def __init__(self, app_window, script):
        self.app_window = app_window
        self.app = app_window.get_app_instance()

        self.loading_library = False

        self.script = script
        self.script.on('message', self.on_message)
        self.script.on('destroyed', self.on_destroyed)

    def on_message(self, message, data):
        if 'payload' not in message:
            print(message)
            return

        what = message['payload']
        parts = what.split(':::')
        if len(parts) < 2:
            print(what)
            return

        if parts[0] == '0':
            self.app.get_log_panel().add_to_main_content_content(parts[1], scroll=True)
        elif parts[0] == '1':
            data = json.loads(parts[1])
            self.app.get_contexts().append(data)

            if 'context' in data:
                sym = ''
                if 'pc' in data['context']:
                    name = data['ptr']
                    self.app.get_hooks_panel().increment_hook_count(data['ptr'])
                    if 'moduleName' in data['symbol']:
                        sym = '(%s - %s)' % (data['symbol']['moduleName'], data['symbol']['name'])
                else:
                    name = data['context']['classMethod']
                    self.app.get_hooks_panel().increment_hook_count(data['context']['classMethod'])
                self.app.get_contexts_panel().add_context(data, library_onload=self.loading_library)
                if self.loading_library is None:
                    self.app.get_log_panel().add_to_main_content_content('hook %s %s @thread := %d' % (
                        name, sym, data['tid']), scroll=True)
                if len(self.app.get_contexts()) > 1:
                    return
            else:
                self.app.arch = data['arch']
                if self.app.get_arch() == 'arm':
                    self.app.pointer_size = 4
                else:
                    self.app.pointer_size = 8
                self.app.get_log_panel().add_to_main_content_content('injected into := ' + str(data['pid']))

            self.app.apply_context(data)
            if self.loading_library is not None:
                self.loading_library = None
        elif parts[0] == '2':
            self.loading_library = parts[1]
            self.app.get_log_panel().add_to_main_content_content('hook onload %s @thread := %s' % (
                parts[1], parts[3]), scroll=True)
            self.app.get_hooks_panel().hit_onload(parts[1], parts[2])
        elif parts[0] == '3':
            self.app.get_hooks_panel().hook_java_callback(parts[1])
        else:
            print(what)

    def on_destroyed(self):
        print('[*] script destroyed')
        self.app_window.close()

    def get_script(self):
        return self.script
