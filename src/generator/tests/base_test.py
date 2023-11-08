import unittest
import os
import subprocess
from pprint import pprint
import frida
import time
from generator import config
import haldump.dump as fhd
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


class TestBaseParamIntrospection(unittest.TestCase):

    DIR = os.path.dirname(os.path.abspath(__file__))
    DATADIR = os.path.join(DIR, "data")
    CFLAGS = ["-Wall", f"-I{config.CLANG_INC_PATH}"]

    def _generate_recorder(self, def_name, base_name):
        interceptor_code = self._generate_interceptor(base_name)
        dumper_code = self._generate_dumper(def_name, base_name)
        recorder = interceptor_code + dumper_code
        with open(
            os.path.join(
                TestBaseParamIntrospection.DATADIR, f"{base_name}_record.js"
            ),
            "wb",
        ) as f:
            f.write(recorder)
        return recorder

    def _generate_interceptor(self, base_name):
        """Start geninterceptor and return java script code."""

        interceptor_args = [
            "python3",
            "-m",
            "generator.geninterceptor",
            os.path.join(
                TestBaseParamIntrospection.DATADIR, f"{base_name}.json"
            ),
        ]
        log.info(
            f"Spawning interceptor subprocess: {' '.join(interceptor_args)}"
        )
        interceptor = subprocess.Popen(interceptor_args, stdout=subprocess.PIPE)
        interceptor_code = interceptor.communicate()[0]
        assert interceptor.returncode == 0, "Interceptor generator failed"
        return interceptor_code

    def _generate_dumper(self, hal_name, base_name):
        """Start gendumper and return java script code for dumping."""

        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = "."
        dumper_args = [
            "python3",
            "-m",
            "generator",
            f"{hal_name}",
            os.path.join(TestBaseParamIntrospection.DATADIR, f"{base_name}.h"),
        ]
        dumper_args.extend(TestBaseParamIntrospection.CFLAGS)
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
        env["LD_PRELOAD"] = os.path.join(
            TestBaseParamIntrospection.DATADIR,
            "frida-gadget-14.2.14-linux-x86_64.so",
        )
        log.info(f"Spawning subprocess for {base_name}.bin")
        binary = subprocess.Popen(
            os.path.join(TestBaseParamIntrospection.DATADIR, f"{base_name}.bin"),
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
        if len(fhd.DATA) != expected_len:
            import ipdb

            ipdb.set_trace()

        import ipdb

        ipdb.set_trace()
        for idx, key in enumerate(fhd.DATA.keys()):
            data = fhd.DATA[key]
            expected_data = expected_values[idx]
            assert data["func"] == expected_data["func"], "func names mismatch"

            onenter_data = data["onEnter"]["params"]
            onleave_data = data["onLeave"]["params"]

            exp_onenter_data = expected_data["onEnter"]["params"]
            exp_onleave_data = expected_data["onLeave"]["params"]

            assert onenter_data == exp_onenter_data, "onenter data mismatch"
            assert onleave_data == exp_onleave_data, "onleave data mismatch"


if __name__ == "__main__":
    unittest.main()
