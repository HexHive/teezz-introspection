import unittest
import os
import subprocess
from pprint import pprint
import frida
import time
from generator import config
import frida_haldump as fhd
import logging

# test-global log configuration
logging.basicConfig(
    format="%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
)

# module-local log setup
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

CFLAGS = ["-Wall", f"-I{config.CLANG_INC_PATH}"]
DIR = os.path.dirname(os.path.abspath(__file__))
DATADIR = os.path.join(DIR, "data")


class TestBaseParamIntrospection(unittest.TestCase):

    """
    Testcase structure:
    1) generate interceptor
        python -m generator.geninterceptor ./generator/tests/data/c_hal.json
    2) generate dumper
        LD_LIBRARY_PATH=. python -m generator.gendumper "mystruct" ./generator/tests/data/c_hal.h -Wall -I/usr/lib/llvm-6.0/lib/clang/6.0.0/include/
    3) concatenate both to get recorder
        cat intercept.js dump.js > recorder.js
    4) start binary (LD_PRELOAD), intercept, dump params
        LD_PRELOAD=./frida-gadget-14.2.14-linux-x86_64.so ./main
        Attach with logic from frida_haldump.py
    5) check if dumped params+retval are correct
    """

    def _generate_interceptor(self, base_name):
        """Start geninterceptor and return java script code."""

        interceptor_args = [
            "python",
            "-m",
            "generator.geninterceptor",
            f"./generator/tests/data/{base_name}.json",
        ]
        log.info(
            f"Spawning interceptor subprocess: {' '.join(interceptor_args)}"
        )
        interceptor = subprocess.Popen(interceptor_args, stdout=subprocess.PIPE)
        interceptor_code = interceptor.communicate()[0]
        return interceptor_code

    def _generate_dumper(self, hal_name, base_name):
        """Start gendumper and return java script code for dumping."""

        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = "."
        dumper_args = [
            "python",
            "-m",
            "generator.gendumper",
            f"{hal_name}",
            f"./generator/tests/data/{base_name}.h",
        ]
        dumper_args.extend(CFLAGS)
        if base_name.startswith("cpp"):
            dumper_args[4] = dumper_args[4] + "pp"

        log.info(f"Spawning gendumper  subprocess: {' '.join(dumper_args)}")
        dumper = subprocess.Popen(dumper_args, stdout=subprocess.PIPE, env=env)
        dumper_code = dumper.communicate()[0]
        assert dumper.returncode == 0, "error in dumper"
        return dumper_code

    def _handle_frida(self, base_name, recorder):
        """Perform function hooking and parameter dumping using frida."""
        fhd.DATA = {}
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = "."
        env[
            "LD_PRELOAD"
        ] = "./generator/tests/data/frida-gadget-14.2.14-linux-x86_64.so"
        log.info(f"Spawning subprocess for {base_name}.bin")
        binary = subprocess.Popen(
            f"./generator/tests/data/{base_name}.bin",
            env=env,
            stdout=subprocess.PIPE,
        )
        # wait for frida-gadget to finish startup
        time.sleep(1)
        # frida setup
        device = frida.get_remote_device()
        device.spawn("re.frida.Gadget")
        session = device.attach("gadget")
        script = session.create_script(recorder.decode())
        script.on("message", fhd.on_message)
        script.load()
        device.resume("gadget")
        # wait for subprocess to terminate
        binary.communicate()[0]
        binary.wait()
        session.detach()

    def _check_dump(self, expected_values, expected_len):
        """Compare dump with expected values."""

        # assert len(DATA) == expected_len, "Wrong number of dumped function calls"

        # import ipdb

        # ipdb.set_trace()
        if len(fhd.DATA) != expected_len:
            import ipdb

            ipdb.set_trace()

        for rand_suffix in fhd.DATA.keys():
            # TODO: per function, check number of dumped parameters
            # TODO: per parameter, check number of dumped leaf nodes
            data = fhd.DATA[rand_suffix]
            expected_data = expected_values[data["func"]][data["dump_id"]]

            # assert len(data["onEnter"]["params"]) == len(
            #     expected_data["onEnter"]
            # ), "Wrong number of dumped parameters on function entry"
            if len(data["onEnter"]["params"]) != len(expected_data["onEnter"]):
                import ipdb

                ipdb.set_trace()

            for p in data["onEnter"]["params"]:
                param = data["onEnter"]["params"][p]
                expected = expected_data["onEnter"][p]

                # assert len(param) == len(
                #     expected
                # ), "Wrong number of fields in the struct on enter"
                if len(param) != len(expected):
                    import ipdb

                    ipdb.set_trace()

                for i in range(len(param)):
                    # assert param[i][1].startswith(expected[i]), "Wrong value on enter"
                    if not param[i][1].startswith(expected[i]):
                        import ipdb

                        ipdb.set_trace()
            assert len(data["onLeave"]["params"]) == len(
                expected_data["onLeave"]
            ), "Wrong number of dumped parameters on leave"
            for p in data["onLeave"]["params"]:
                param = data["onLeave"]["params"][p]
                expected = expected_data["onLeave"][p]
                assert len(param) == len(
                    expected
                ), "Wrong number of fields in the struct on leave"
                for i in range(len(param)):
                    # assert param[i][1].startswith(expected[i]), "Wrong value on leave"
                    if not param[i][1].startswith(expected[i]):
                        import ipdb

                        ipdb.set_trace()


if __name__ == "__main__":
    unittest.main()
