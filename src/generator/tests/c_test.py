import os
import struct
from pprint import pprint
import time
from generator import config
import logging
from collections import OrderedDict
from .base_test import TestBaseParamIntrospection

# test-global log configuration
logging.basicConfig(
    format="%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
)

# module-local log setup
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class TestCParamIntrospection(TestBaseParamIntrospection):
    def test_hook_c_hal(self):
        """test if hook yields `int a` and `int b` of myfunc."""
        base_name = "c/c_hal"
        recorder = self._generate_recorder("mystruct", base_name)
        self._handle_frida(base_name, recorder)

        expected_values = [
            {
                "ctx_closed": True,
                "dump_id": 0,
                "func": "myfunc",
                "onEnter": {
                    "params": {
                        "a": {
                            "ctx_closed": True,
                            "data": {"a": b"\x03\x00\x00\x00"},
                            "type": "int",
                        },
                        "b": {
                            "ctx_closed": True,
                            "data": {"b": b"\x04\x00\x00\x00"},
                            "type": "int",
                        },
                    }
                },
                "onLeave": {
                    "params": {
                        "a": {
                            "ctx_closed": True,
                            "data": {"a": b"\x03\x00\x00\x00"},
                            "type": "int",
                        },
                        "b": {
                            "ctx_closed": True,
                            "data": {"b": b"\x04\x00\x00\x00"},
                            "type": "int",
                        },
                        "ret": {
                            "ctx_closed": True,
                            "data": {"ret": b"\x07\x00\x00\x00"},
                            "type": "int",
                        },
                    }
                },
            }
        ]

        self._check_dump(expected_values, 1)

    def test_hook_c_hal_typedef(self):
        """test if hook yields parameters a and b of myfunc."""
        base_name = "c/c_hal_typedef"

        recorder = self._generate_recorder("MyStruct", base_name)
        self._handle_frida(base_name, recorder)
        # wait for frida sending all onleave messages
        time.sleep(1)

        expected_values = [
            {
                "ctx_closed": True,
                "dump_id": 0,
                "func": "myfunc",
                "onEnter": {
                    "params": {
                        "a": {
                            "ctx_closed": True,
                            "data": OrderedDict(
                                [
                                    (
                                        "a",
                                        {
                                            "data": b"\x00\x00\x00\x00"
                                            b"\x00\x00\x00\x00",
                                            "type": "unsigned " "long",
                                        },
                                    )
                                ]
                            ),
                            "nesting": [],
                            "type": "struct SomeStruct",
                        },
                        "b": {
                            "ctx_closed": True,
                            "data": OrderedDict(
                                [
                                    (
                                        "b",
                                        {
                                            "data": b"\x08\x00\x00\x00"
                                            b"\x00\x00\x00\x00",
                                            "type": "unsigned " "long",
                                        },
                                    )
                                ]
                            ),
                            "nesting": [],
                            "type": "struct SomeStruct",
                        },
                    }
                },
                "onLeave": {
                    "params": {
                        "a": {
                            "ctx_closed": True,
                            "data": OrderedDict(
                                [
                                    (
                                        "a",
                                        {
                                            "data": b"\x08\x00\x00\x00"
                                            b"\x00\x00\x00\x00",
                                            "type": "unsigned " "long",
                                        },
                                    )
                                ]
                            ),
                            "nesting": [],
                            "type": "struct SomeStruct",
                        },
                        "b": {
                            "ctx_closed": True,
                            "data": OrderedDict(
                                [
                                    (
                                        "b",
                                        {
                                            "data": b"\x08\x00\x00\x00"
                                            b"\x00\x00\x00\x00",
                                            "type": "unsigned " "long",
                                        },
                                    )
                                ]
                            ),
                            "nesting": [],
                            "type": "struct SomeStruct",
                        },
                        "ret": {
                            "ctx_closed": True,
                            "data": b"\x00\x00\x00\x00",
                            "type": "int",
                        },
                    }
                },
                "time": "2023-08-29_11-51-21",
            }
        ]

        self._check_dump(expected_values, 1)

    def test_hook_c_hal_complex(self):
        """test if hook yields parameters 'a' and 'b' of both functions."""
        base_name = "c/c_hal_complex"

        recorder = self._generate_recorder("MyStruct", base_name)
        self._handle_frida(base_name, recorder)

        expected_values = {
            "myfuncptr": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x04\x00\x00\x00",
                            b"\x06\x00\x00\x00",
                            b"\x08\x00\x00\x00",
                            b"\x10\x00\x00\x00\x00\x00\x00\x00",
                        ],
                        "b": [
                            b"\x04\x00\x00\x00",
                            b"\x06\x00\x00\x00",
                            b"\x08\x00\x00\x00",
                            b"\x10\x00\x00\x00\x00\x00\x00\x00",
                            b"\x18\x00\x00\x00\x00\x00\x00\x00",
                        ],
                    },
                    "onLeave": {
                        "a": [
                            b"\x04\x00\x00\x00",
                            b"\x06\x00\x00\x00",
                            b"\x08\x00\x00\x00",
                            b"\x10\x00\x00\x00\x00\x00\x00\x00",
                        ],
                        "b": [
                            b"\x04\x00\x00\x00",
                            b"\x06\x00\x00\x00",
                            b"\x08\x00\x00\x00",
                            b"\x10\x00\x00\x00\x00\x00\x00\x00",
                            b"\x18\x00\x00\x00\x00\x00\x00\x00",
                        ],
                        "myfuncptr": [b"\x28\x00\x00\x00"],
                    },
                },
            },
            "myfuncptr2": {
                1: {
                    "onEnter": {
                        "a": [
                            b"\x04\x00\x00\x00",
                            b"\x06\x00\x00\x00",
                            b"\x08\x00\x00\x00",
                            b"\x10\x00\x00\x00\x00\x00\x00\x00",
                            b"\x18\x00\x00\x00\x00\x00\x00\x00",
                        ],
                        "b": [
                            b"\x04\x00\x00\x00",
                            b"\x06\x00\x00\x00",
                            b"\x08\x00\x00\x00",
                        ],
                    },
                    "onLeave": {
                        "a": [
                            b"\x04\x00\x00\x00",
                            b"\x06\x00\x00\x00",
                            b"\x08\x00\x00\x00",
                            b"\x10\x00\x00\x00\x00\x00\x00\x00",
                            b"\x18\x00\x00\x00\x00\x00\x00\x00",
                        ],
                        "b": [
                            b"\x04\x00\x00\x00",
                            b"\x06\x00\x00\x00",
                            b"\x08\x00\x00\x00",
                        ],
                        "myfuncptr2": [b"\x0c\x00\x00\x00"],
                    },
                }
            },
        }
        self._check_dump(expected_values, 2)

    def test_hook_c_hal_enum(self):
        """test if hook yields parameters 'a' and 'b' of all function calls."""
        base_name = "c/c_hal_enum"

        recorder = self._generate_recorder("MyStruct", base_name)
        self._handle_frida(base_name, recorder)

        expected_values = {
            "myfunc_a": {
                0: {
                    "onEnter": {
                        "a": [b"\x01\x00\x00\x00"],
                        "b": [b"\x02\x00\x00\x00"],
                    },
                    "onLeave": {
                        "myfunc_a": [b"\x00\x00\x00\x00"],
                        "a": [b"\x01\x00\x00\x00"],
                        "b": [b"\x02\x00\x00\x00"],
                    },
                },
                1: {
                    "onEnter": {
                        "a": [b"\x00\x02\x00\x00"],
                        "b": [b"\x04\x00\x00\x00"],
                    },
                    "onLeave": {
                        "myfunc_a": [b"\x00\x00\x00\x00"],
                        "a": [b"\x00\x02\x00\x00"],
                        "b": [b"\x04\x00\x00\x00"],
                    },
                },
                2: {
                    "onEnter": {
                        "a": [b"\x00\x00\x00\xa0"],
                        "b": [b"\x06\x00\x00\x00"],
                    },
                    "onLeave": {
                        "myfunc_a": [b"\x00\x00\x00\x00"],
                        "a": [b"\x00\x00\x00\xa0"],
                        "b": [b"\x06\x00\x00\x00"],
                    },
                },
            }
        }
        self._check_dump(expected_values, 3)

    def test_hook_c_hal_pointer(self):
        """test if hook yields the second parameter of all functions."""
        base_name = "c/c_hal_pointer"

        recorder = self._generate_recorder("MyStruct", base_name)
        self._handle_frida(base_name, recorder)

        expected_values = {
            "func_a": {
                0: {
                    "onEnter": {"a": [b"\x02\x00\x00\x00"]},
                    "onLeave": {
                        "func_a": [b"\x00\x00\x00\x00"],
                        "a": [b"\x04\x00\x00\x00"],
                    },
                }
            },
            "func_b": {
                1: {
                    "onEnter": {"b": [b"\x04\x00\x00\x00"]},
                    "onLeave": {
                        "func_b": [b"\x00\x00\x00\x00"],
                        "b": [b"\x04\x00\x00\x00"],
                    },
                }
            },
            "func_c": {
                2: {
                    "onEnter": {
                        "a": [b"\x05\x00\x00\x00\x00\x00\x00\x00", b"\x04\x00"]
                    },
                    "onLeave": {
                        "func_c": [b"\x00\x00\x00\x00"],
                        "a": [b"\x10\x00\x00\x00\x00\x00\x00\x00", b"\x05\x00"],
                    },
                }
            },
        }
        self._check_dump(expected_values, 3)

    def test_hook_c_hal_primitive_types(self):
        """test if hook yields the second parameter of all functions."""
        base_name = "c/c_hal_primitive_types"

        recorder = self._generate_recorder("MyStruct", base_name)
        self._handle_frida(base_name, recorder)

        float_val = struct.pack("f", 3.4)
        double_val = struct.pack("d", 5.6)
        expected_values = {
            "bytes": {
                0: {
                    "onEnter": {"a": [b"\x0a"], "b": [b"\x01"], "c": [b"\x00"]},
                    "onLeave": {
                        "bytes": [b"\x00\x00\x00\x00"],
                        "a": [b"\x0a"],
                        "b": [b"\x01"],
                        "c": [b"\x0b"],
                    },
                }
            },
            "shorts": {
                1: {
                    "onEnter": {
                        "a": [b"\x01\x00"],
                        "b": [b"\x02\x00"],
                        "c": [b"\x00\x00"],
                    },
                    "onLeave": {
                        "shorts": [b"\x00\x00\x00\x00"],
                        "a": [b"\x01\x00"],
                        "b": [b"\x02\x00"],
                        "c": [b"\x03\x00"],
                    },
                }
            },
            "ints": {
                2: {
                    "onEnter": {
                        "a": [b"\x03\x00\x00\x00"],
                        "b": [b"\x04\x00\x00\x00"],
                        "c": [b"\x05\x00\x00\x00"],
                        "d": [b"\x00\x00\x00\x00"],
                    },
                    "onLeave": {
                        "ints": [b"\x00\x00\x00\x00"],
                        "a": [b"\x03\x00\x00\x00"],
                        "b": [b"\x04\x00\x00\x00"],
                        "c": [b"\x05\x00\x00\x00"],
                        "d": [b"\x0c\x00\x00\x00"],
                    },
                }
            },
            "longs": {
                3: {
                    "onEnter": {
                        "a": [b"\x06\x00\x00\x00\x00\x00\x00\x00"],
                        "b": [b"\x07\x00\x00\x00\x00\x00\x00\x00"],
                        "c": [b"\x08\x00\x00\x00\x00\x00\x00\x00"],
                        "d": [b"\x00\x00\x00\x00\x00\x00\x00\x00"],
                    },
                    "onLeave": {
                        "longs": [b"\x00\x00\x00\x00"],
                        "a": [b"\x06\x00\x00\x00\x00\x00\x00\x00"],
                        "b": [b"\x07\x00\x00\x00\x00\x00\x00\x00"],
                        "c": [b"\x08\x00\x00\x00\x00\x00\x00\x00"],
                        "d": [b"\x15\x00\x00\x00\x00\x00\x00\x00"],
                    },
                }
            },
            "bools": {
                4: {
                    "onEnter": {"a": [b"\x01"], "b": [b"\x00"]},
                    "onLeave": {
                        "bools": [b"\x00\x00\x00\x00"],
                        "a": [b"\x01"],
                        "b": [b"\x01"],
                    },
                }
            },
            # "floats": {
            #    5: {
            #        "onEnter": {"a": [float_val], "b": [b"\x00\x00\x00\x00"]},
            #        "onLeave": {
            #            "floats": [b"\x00\x00\x00\x00"],
            #            "a": [float_val],
            #            "b": [float_val],
            #        },
            #    }
            # },
            # "doubles": {
            #    6: {
            #        "onEnter": {
            #            "a": [double_val],
            #            "b": [b"\x00\x00\x00\x00\x00\x00\x00\x00"],
            #        },
            #        "onLeave": {
            #            "doubles": [b"\x00\x00\x00\x00"],
            #            "a": [double_val],
            #            "b": [double_val],
            #        },
            #    }
            # },
        }
        self._check_dump(expected_values, 5)

    def test_hook_c_hal_array(self):
        """test if hook yields the second parameter of all functions."""
        base_name = "c/c_hal_array"

        recorder = self._generate_recorder("MyStruct", base_name)
        self._handle_frida(base_name, recorder)

        expected_values = {
            "func_a": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x01\x00\x00\x00\x02\x00\x00\x00"
                            b"\x03\x00\x00\x00\x04\x00\x00\x00",
                            b"\x05\x00\x00\x00\x00\x00\x00\x00"
                            b"\x06\x00\x00\x00\x00\x00\x00\x00"
                            b"\x07\x00\x00\x00\x00\x00\x00\x00"
                            b"\x08\x00\x00\x00\x00\x00\x00\x00"
                            b"\x09\x00\x00\x00\x00\x00\x00\x00"
                            b"\x0a\x00\x00\x00\x00\x00\x00\x00",
                        ],
                        "b": [
                            b"\x0a\x00\x00\x00\x09\x00\x00\x00"
                            b"\x08\x00\x00\x00\x07\x00\x00\x00",
                            b"\x06\x00\x00\x00\x00\x00\x00\x00"
                            b"\x05\x00\x00\x00\x00\x00\x00\x00"
                            b"\x04\x00\x00\x00\x00\x00\x00\x00"
                            b"\x03\x00\x00\x00\x00\x00\x00\x00"
                            b"\x02\x00\x00\x00\x00\x00\x00\x00"
                            b"\x01\x00\x00\x00\x00\x00\x00\x00",
                        ],
                    },
                    "onLeave": {
                        "func_a": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x0a\x00\x00\x00\x09\x00\x00\x00"
                            b"\x08\x00\x00\x00\x07\x00\x00\x00",
                            b"\x06\x00\x00\x00\x00\x00\x00\x00"
                            b"\x05\x00\x00\x00\x00\x00\x00\x00"
                            b"\x04\x00\x00\x00\x00\x00\x00\x00"
                            b"\x03\x00\x00\x00\x00\x00\x00\x00"
                            b"\x02\x00\x00\x00\x00\x00\x00\x00"
                            b"\x01\x00\x00\x00\x00\x00\x00\x00",
                        ],
                        "b": [
                            b"\x01\x00\x00\x00\x02\x00\x00\x00"
                            b"\x03\x00\x00\x00\x04\x00\x00\x00",
                            b"\x05\x00\x00\x00\x00\x00\x00\x00"
                            b"\x06\x00\x00\x00\x00\x00\x00\x00"
                            b"\x07\x00\x00\x00\x00\x00\x00\x00"
                            b"\x08\x00\x00\x00\x00\x00\x00\x00"
                            b"\x09\x00\x00\x00\x00\x00\x00\x00"
                            b"\x0a\x00\x00\x00\x00\x00\x00\x00",
                        ],
                    },
                }
            }
        }
        self._check_dump(expected_values, 1)

    def test_hook_c_hal_callback(self):
        """test if hook yields the address of the callback function."""
        base_name = "c/c_hal_callback"

        recorder = self._generate_recorder("MyStruct", base_name)
        self._handle_frida(base_name, recorder)

        expected_values = {
            "func_a": {
                0: {"onEnter": {}, "onLeave": {"func_a": [b"\x00\x00\x00\x00"]}}
            }
        }
        self._check_dump(expected_values, 1)

    def test_hook_c_hal_union(self):
        """test if hook yields parameter a of the function."""
        base_name = "c/c_hal_union"

        recorder = self._generate_recorder("MyStruct", base_name)
        self._handle_frida(base_name, recorder)
        expected_values = {
            "func_a": {
                0: {
                    "onEnter": {
                        "a": [
                            b"\x01\x00\x00\x00",
                            b"\x88\x77\x66\x55\x44\x33\x22\x11",
                            b"\x04\x00\x00\x00\x00\x00\x00\x00",
                        ]
                    },
                    "onLeave": {
                        "func_a": [b"\x00\x00\x00\x00"],
                        "a": [
                            b"\x0a\x00\x00\x00",
                            b"\xe9\x77\x66\x55\x44\x33\x22\x11",
                            b"\x06\x00\x00\x00\x00\x00\x00\x00",
                        ],
                    },
                }
            }
        }
        self._check_dump(expected_values, 1)
