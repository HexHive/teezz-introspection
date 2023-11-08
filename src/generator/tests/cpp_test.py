import os
import struct
from pprint import pprint
from generator import config
import logging
from .base_test import TestBaseParamIntrospection

p32 = lambda x: struct.pack("<I", x)
p64 = lambda x: struct.pack("<Q", x)

# test-global log configuration
logging.basicConfig(
    format="%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
)

# module-local log setup
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class TestCPPParamIntrospection(TestBaseParamIntrospection):
    def test_hook_cpp_hal(self):
        """test if hook yields `int a` and `int b` of myfunc."""
        base_name = "cpp/cpp_hal"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "myfunc": {
                0: {
                    "onEnter": {
                        "a": [b"\x03\x00\x00\x00"],
                        "b": [b"\x04\x00\x00\x00"],
                    },
                    "onLeave": {
                        "myfunc": [b"\x00\x00\x00\x00"],
                        "a": [b"\x03\x00\x00\x00"],
                        "b": [b"\x04\x00\x00\x00"],
                    },
                }
            }
        }
        self._check_dump(expected_values, 1)

    def test_hook_cpp_hal_complex(self):
        """test if hook yields parameter a of myfunc."""
        base_name = "cpp/cpp_hal_complex"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "myfunc": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x0a\x00\x00\x00",
                            b"\x0b\x00\x00\x00",
                            b"\x0c\x00\x00\x00",
                            b"\x01\x00\x00\x00\x00\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                        ]
                    },
                    "onLeave": {
                        "myfunc": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\xff\xff\xff\xff",
                            b"\x0b\x00\x00\x00",
                            b"\x0c\x00\x00\x00",
                            b"\x06\x00\x00\x00\x00\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                        ],
                    },
                }
            }
        }
        self._check_dump(expected_values, 1)

    def test_hook_cpp_hal_enum(self):
        """test if hook yields parameters en_val and b of myfunc."""
        base_name = "cpp/cpp_hal_enum"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "myfunc": {
                0: {
                    "onEnter": {
                        "en_val": [b"\x00\x00\x00\x00"],
                        "b": [b"\x05\x00\x00\x00\x00\x00\x00\x00"],
                    },
                    "onLeave": {
                        "myfunc": [b"\x05\x00\x00\x00"],
                        "en_val": [b"\x00\x00\x00\x00"],
                        "b": [b"\x05\x00\x00\x00\x00\x00\x00\x00"],
                    },
                },
                1: {
                    "onEnter": {
                        "en_val": [b"\x00\x0f\x00\x00"],
                        "b": [b"\x05\x00\x00\x00\x00\x00\x00\x00"],
                    },
                    "onLeave": {
                        "myfunc": [b"\x06\x00\x00\x00"],
                        "en_val": [b"\x00\x0f\x00\x00"],
                        "b": [b"\x05\x00\x00\x00\x00\x00\x00\x00"],
                    },
                },
            }
        }
        self._check_dump(expected_values, 2)

    def test_hook_cpp_hal_array(self):
        """test if hook yields parameters of all functions."""
        base_name = "cpp/cpp_hal_array"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "func_a": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x01\x02",
                            b"\x03\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00",
                            b"\x06\x00\x07\x00\x08\x00",
                        ],
                        "b": [
                            b"\x01\x02",
                            b"\x03\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00",
                            b"\x06\x00\x07\x00\x08\x00",
                        ],
                    },
                    "onLeave": {
                        "func_a": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x02\x02",
                            b"\x04\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00",
                            b"\x06\x00\x07\x00\x08\x00",
                        ],
                        "b": [
                            b"\x02\x02",
                            b"\x04\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00",
                            b"\x06\x00\x07\x00\x08\x00",
                        ],
                    },
                }
            },
            "func_b": {
                1: {
                    "onEnter": {
                        "a": [
                            b"\x04\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00",
                            b"\x06\x00\x07\x00\x08\x00",
                        ],
                        "b": [
                            b"\x0d\x00\x00\x00\x0e\x00\x00\x00\x0f\x00\x00\x00",
                            b"\x10\x00\x11\x00\x12\x00",
                        ],
                    },
                    "onLeave": {
                        "func_b": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x04\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00",
                            b"\x06\x00\x07\x00\x08\x00",
                        ],
                        "b": [
                            b"\x0d\x00\x00\x00\x04\x00\x00\x00\x0f\x00\x00\x00",
                            b"\x10\x00\x11\x00\x08\x00",
                        ],
                    },
                }
            },
        }
        self._check_dump(expected_values, 2)

    def test_hook_cpp_hal_extended(self):
        """test if hook yields parameters of all functions."""
        base_name = "cpp/cpp_hal_extended"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        float_val = struct.pack("f", 3.4)
        expected_values = {
            # "simple_func": {
            #     0: {
            #         "onEnter": {"a": [b"\x07\x00\x00\x00"], "b": [float_val]},
            #         "onLeave": {
            #             "simple_func": [float_val],
            #             "a": [b"\x07\x00\x00\x00"],
            #             "b": [float_val],
            #         },
            #     }
            # },
            "class_arg": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                        ],
                        "b": [
                            b"\x0a\x00\x00\x00",
                            b"\x0b\x00\x00\x00\x00\x00\x00\x00",
                        ],
                    },
                    "onLeave": {
                        "class_arg": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x0a\x00\x00\x00",
                            b"\x0b\x00\x00\x00\x00\x00\x00\x00",
                        ],
                        "b": [
                            b"\x0a\x00\x00\x00",
                            b"\x0b\x00\x00\x00\x00\x00\x00\x00",
                        ],
                    },
                }
            },
            "class_ptr": {
                1: {
                    "onEnter": {
                        "a": [
                            b"\x0a\x00\x00\x00",
                            b"\x0b\x00\x00\x00\x00\x00\x00\x00",
                        ]
                    },
                    "onLeave": {
                        "class_ptr": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x05\x00\x00\x00",
                            b"\xff\xff\xff\xff\xff\xff\xff\xff",
                        ],
                    },
                }
            },
        }
        self._check_dump(expected_values, 2)

    def test_hook_cpp_hal_hierarchy(self):
        """test if hook yields parameters of all functions."""
        base_name = "cpp/cpp_hal_hierarchy"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "func_a": {
                0: {
                    "onEnter": {
                        "a": [
                            b"a",
                            b"\x05\x00\x00\x00\x00\x00\x00\x00",
                            b"\x02\x00",
                            b"\x03\x00\x00\x00",
                        ],
                        "b": [
                            b"b",
                            b"\x0a\x00\x00\x00\x00\x00\x00\x00",
                            b"\x04\x00",
                            b"\x06\x00\x00\x00",
                        ],
                    },
                    "onLeave": {
                        "func_a": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"b",
                            b"\xff\x00\x00\x00\x00\x00\x00\x00",
                            b"\x02\x00",
                            b"\x06\x00\x00\x00",
                        ],
                        "b": [
                            b"b",
                            b"\x0a\x00\x00\x00\x00\x00\x00\x00",
                            b"\x04\x00",
                            b"\x06\x00\x00\x00",
                        ],
                    },
                }
            },
            "func_b": {
                1: {
                    "onEnter": {
                        "a": [b"a", b"\xff\x00\x00\x00\x00\x00\x00\x00"],
                        "b": [b"\x02\x00", b"\x06\x00\x00\x00"],
                    },
                    "onLeave": {
                        "func_b": [b"\x00\x00\x00\x00"],
                        "a": [b"a", b"\x02\x00\x00\x00\x00\x00\x00\x00"],
                        "b": [b"\x02\x00", b"\x06\x00\x00\x00"],
                    },
                }
            },
        }
        self._check_dump(expected_values, 2)

    def test_hook_cpp_hal_parameter(self):
        """test if hook yields parameter a of myfunc."""
        base_name = "cpp/cpp_hal_parameter"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "myfunc": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x01\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x0b\x00\x00\x00",
                        ]
                    },
                    "onLeave": {
                        "myfunc": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x00\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x2a\x00\x00\x00",
                        ],
                    },
                }
            }
        }
        self._check_dump(expected_values, 1)

    def test_hook_cpp_hal_pointer(self):
        """test if hook yields parameters of all functions."""
        base_name = "cpp/cpp_hal_pointer"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "func_a": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x05\x00\x00\x00",
                        ],
                        "b": [
                            b"\x0a\x00\x00\x00\x00\x00\x00\x00",
                        ],
                    },
                    "onLeave": {
                        "func_a": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x05\x00\x00\x00",
                        ],
                        "b": [
                            b"\x05\x00\x00\x00\x00\x00\x00\x00",
                        ],
                    },
                }
            },
            "func_b": {
                1: {
                    "onEnter": {
                        "a": [b"\x04\x00", b"a\x00"],
                        "b": [b"\x06\x00", b"b\x00"],
                    },
                    "onLeave": {
                        "func_b": [b"\x00\x00\x00\x00"],
                        "a": [b"\x04\x00", b"a\x00"],
                        "b": [b"\x04\x00", b"a\x00"],
                    },
                }
            },
            "func_c": {
                2: {
                    "onEnter": {
                        "a": [b"\x04\x00", b"a\x00", b"\x01\x00\x00\x00"],
                        "b": [b"\x06\x00", b"b\x00", b"\x02\x00\x00\x00"],
                    },
                    "onLeave": {
                        "func_c": [b"\x00\x00\x00\x00"],
                        "a": [b"\x06\x00", b"b\x00", b"\x02\x00\x00\x00"],
                        "b": [b"\x06\x00", b"b\x00", b"\x02\x00\x00\x00"],
                    },
                }
            },
        }
        self._check_dump(expected_values, 3)

    def test_hook_cpp_hal_struct(self):
        """test if hook yields parameters of all functions."""
        base_name = "cpp/cpp_hal_struct"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "func_a": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x07\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x07\x00",
                        ],
                        "b": [
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x08\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x08\x00",
                        ],
                    },
                    "onLeave": {
                        "func_a": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x07\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x07\x00",
                        ],
                        "b": [
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x08\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x08\x00",
                        ],
                    },
                }
            },
            "func_b": {
                1: {
                    "onEnter": {
                        "a": [
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                        ],
                        "b": [
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x08\x00",
                        ],
                    },
                    "onLeave": {
                        "func_b": [b"\x00\x00\x00\x00\x00\x00\x00\x00"],
                        "a": [
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                        ],
                        "b": [
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x09\x00",
                        ],
                    },
                }
            },
            "func_c": {
                2: {
                    "onEnter": {
                        "a": [
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x07\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                        ],
                        "b": [
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x08\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                        ],
                    },
                    "onLeave": {
                        "func_c": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x06\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x07\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x01\x00\x00\x00",
                            b"\x02\x00\x00\x00\x00\x00\x00\x00",
                            b"a\x00",
                            b"\x05\x00\x00\x00",
                        ],
                        "b": [
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x08\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x03\x00\x00\x00",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                            b"b\x00",
                            b"\x06\x00\x00\x00",
                        ],
                    },
                }
            },
        }
        self._check_dump(expected_values, 3)

    def test_hook_cpp_hal_template(self):
        """test if hook yields parameter a of myfunc."""
        base_name = "cpp/cpp_hal_template"
        recorder = self._generate_recorder("MyStruct", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "myfunc": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x04\x00\x00\x00",
                        ]
                    },
                    "onLeave": {
                        "myfunc": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x05\x00\x00\x00",
                        ],
                    },
                }
            }
        }
        self._check_dump(expected_values, 1)

    def test_hook_cpp_hal_union(self):
        """test if hook yields parameters of all functions."""
        base_name = "cpp/cpp_hal_union"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "func_a": {
                0: {
                    "onEnter": {
                        "a": [b"\x01\x00", b"\x98\x98\x98\x98", b"b\x00"]
                    },
                    "onLeave": {
                        "func_a": [p32(0)],
                        "a": [b"\x98\xff", b"\x0b\x00\x00\x00", b"b\x00"],
                    },
                }
            },
            "func_b": {
                1: {
                    "onEnter": {
                        "a": [
                            p32(2),
                            b"\xfe\xca\xef\xbe\xad\xde\x37\x13",
                            p64(3),
                        ]
                    },
                    "onLeave": {
                        "func_b": [p32(0)],
                        "a": [
                            b"\xfe\xca\xef\xbe",
                            p64(3),
                            p64(3),
                        ],
                    },
                }
            },
        }
        self._check_dump(expected_values, 2)

    def test_hook_cpp_hal_szunion(self):
        """record `char*` in `union` depending on `sz` field in same struct."""
        base_name = "cpp/cpp_hal_szunion"
        recorder = self._generate_recorder("MyStructFunc", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "myfunc": {
                0: {
                    "onEnter": {"a": [b"A" * 16, p32(16)]},
                    "onLeave": {
                        "myfunc": [p32(0)],
                        "a": [b"B" * 16, p32(16)],
                    },
                }
            },
        }
        self._check_dump(expected_values, 1)

    def test_hook_cpp_hal_callback(self):
        """test if hook yields parameters of all functions."""
        base_name = "cpp/cpp_hal_callback"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            # "func_a": {
            #     0: {
            #         "onEnter": {"b": [b"\x62"]},
            #         "onLeave": {"b": [b"\x62"], "func_a": [b"\x00\x00\x00\x00"]},
            #     }
            # },
            "func_b": {
                1: {
                    "onEnter": {"b": [b"\x00\x00\x00\x00"]},
                    "onLeave": {
                        "b": [b"\x00\x00\x00\x00"],
                        "func_a": [b"\x00\x00\x00\x00"],
                    },
                }
            },
            # "func_c": {
            #     2: {
            #         "onEnter": {"b": [b"\x01\x00\x00\x00\x00\x00\x00\x00"]},
            #         "onLeave": {
            #             "b": [b"\x01\x00\x00\x00\x00\x00\x00\x00"],
            #             "func_c": [b"\x00\x00\x00\x00"],
            #         },
            #     }
            # },
        }
        self._check_dump(expected_values, 3)

    def test_hook_cpp_hal_struct_array(self):
        """test if hook yields parameters of all functions."""
        base_name = "cpp/cpp_hal_struct_array"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "func_b": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x01\x00\x00\x00\x02\x00\x00\x00"
                            b"\x03\x00\x00\x00\x0b\x00\x00\x00"
                            b"\x0c\x00\x00\x00\x0d\x00\x00\x00"
                        ],
                        "b": [
                            b"\x15\x00\x00\x00\x16\x00\x00\x00"
                            b"\x17\x00\x00\x00\x1f\x00\x00\x00"
                            b"\x20\x00\x00\x00\x21\x00\x00\x00"
                        ],
                    },
                    "onLeave": {
                        "func_b": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x01\x00\x00\x00\x02\x00\x00\x00"
                            b"\x03\x00\x00\x00\x0b\x00\x00\x00"
                            b"\x0c\x00\x00\x00\x0d\x00\x00\x00"
                        ],
                        "b": [
                            b"\x0b\x00\x00\x00\x0c\x00\x00\x00"
                            b"\x0d\x00\x00\x00\x1f\x00\x00\x00"
                            b"\x20\x00\x00\x00\x21\x00\x00\x00"
                        ],
                    },
                }
            }
        }
        self._check_dump(expected_values, 1)

    def test_hook_cpp_hal_nestedsz(self):
        """test recording for nested sz fields of vectors."""
        base_name = "cpp/cpp_hal_nestedsz"
        recorder = self._generate_recorder("MyHAL", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "func_a": {
                0: {
                    "onEnter": {
                        "params": [
                            b"\xaa" * 4,
                            p32(0xDEADBEEF),
                            b"\xbb" * 4,
                            b"",
                            "".join(
                                [chr(i) for i in range(0x41, 0x61)]
                            ).encode(),
                        ],
                    },
                    "onLeave": {
                        "func_a": [b"\x00\x00\x00\x00"],
                        "params": [
                            b"\xaa" * 4,
                            p32(0xDEADBEEF),
                            b"\xbb" * 4,
                            b"",
                            "".join(
                                [chr(i) for i in range(0x41, 0x61)]
                            ).encode(),
                        ],
                    },
                }
            }
        }
        self._check_dump(expected_values, 1)
