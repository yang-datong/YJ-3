#!/usr/local/bin/python3.9
from common.cmd import *
import frida

LAYOUT_SCRIPT_FILE = "common/layout.js"
UTILITY_SCRIPT_FILE = "common/utility.js"
SNAPSHOT_FILE = ".snapshot/YJ.snapshot"

# -------------------------- Main --------------------------

# Initialization style theme
layout = LayoutView()


def on_message(message, data):
    if message['type'] == 'send':
        layout.check_is_view_tag(message)
        if (layout.check_is_need_clear_view() == True):
            return
        if (layout.check_is_init_segment_address() == True):
            return
        layout.show_line_view()
        layout.reset_send_payload(message)
        if LayoutView.tele_tag in layout.payload:
            layout.show_tele_view()
        elif LayoutView.register_tag in layout.payload:
            layout.show_registers_view()
        elif LayoutView.code_tag in layout.payload:
            layout.show_code_view()
        elif LayoutView.trace_tag in layout.payload:
            layout.show_trace_view()
        else:
            layout.payload = str(message['payload'])  # 还原数组
            print("\033[31m{0}\033[0m".format(layout.payload))
    else:
        print(message)


def saveSnapshot(process):
    try:
        config_files = [LAYOUT_SCRIPT_FILE, UTILITY_SCRIPT_FILE]
        script = ''

        for file in config_files:
            with open(file, 'r') as f:
                content = f.read()
            script += content

        snapshot = process.snapshot_script(
            script, warmup_script="true", runtime="v8")
        # Create local snapshot
        print("Snapshot created! Size:", len(snapshot))
        file = open(SNAPSHOT_FILE, 'wb')
        file.write(snapshot)
        file.close()
    except Exception as e:
        print("saveSnapshot() error" + e)
        os.popen("bash common/md5.sh -c")


def main(args):
    load_script = args.load
    app = args.app
    is_spawn_model = args.spawn_model
    breakpointer = args.breakpoint

    device = frida.get_usb_device()

    # open -spawn_model use spawn attach application
    if is_spawn_model:
        pid = device.get_process(app).pid
        pack = os.popen(
            "adb shell \"ps -p %s -w | grep %s | awk '{print \$NF}'\"" % (pid, pid)).readlines()[0]
        app = device.spawn(pack.replace('\n', ''))

    process = device.attach(app)
    # process.enable_debugger() #TODO

    # Check to see if a local snapshot exists or if the snapshot has changed (md5 realize)
    isChangeFile = os.popen(
        "bash common/md5.sh " + LAYOUT_SCRIPT_FILE + " " + UTILITY_SCRIPT_FILE).readlines()[0]

    if isChangeFile != "0":
        # print("Change File call saveSnapshot()")
        saveSnapshot(process)
    # else:
    #    print("Use before snapshot")

    if os.path.isfile(SNAPSHOT_FILE):
        # Live snapshot
        with open(SNAPSHOT_FILE, "rb") as f:
            _snapshot = f.read()
    else:
        saveSnapshot(process)
        print(RED("Snapshot file is missing . Try again"))
        exit(0)

    with open(load_script, 'r') as f:
        script = f.read()
    f.close()

    script = process.create_script(script, snapshot=_snapshot, runtime='v8')
    script.on('message', on_message)
    script.load()
    show_head_view_tips_info_color()
    script.exports.init(LayoutView.mjson)

    # Whether need to set pre-breakpoint
    if not breakpointer is None:
        info = format_breakpoint(breakpointer)
        script.exports.set_breakpoint(info[1], info[0])

    # Into Interaction Model
    it = Interaction(device, script, is_spawn_model, app)
    it.start()
