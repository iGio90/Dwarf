class Tool:

    def __init__(self):
        from dwarf_debugger.lib import glue

        self.arguments_parser = glue.initialize_arg_parser()
        self.parse_arguments(self.arguments_parser)
        self.arguments = self.arguments_parser.parse_args()

        if not self.arguments.target and not self.arguments.device:
            print('missing session type. use -t local|android|ios|remote to define the session type'
                  ' or specify a device id with --device')
            exit(0)

        if self.arguments.any == '':
            print('missing file or package name to attach')
            exit(0)

        user_script = self.get_script()
        glue.attach_spawn_target(self.arguments, user_script)

    def parse_arguments(self, parser):
        pass

    def get_script(self):
        pass
