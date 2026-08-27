from __future__ import annotations

import unittest
from collections import OrderedDict

import archinfo

import angr
import angr.rust.knowledge_plugins  # pylint:disable=unused-import
from angr.analyses.typehoon import typeconsts
from angr.rust.analyses.type_db_loader import TypeDBLoader
from angr.rust.sim_type import (
    EnumVariant,
    RustSimEnum,
    RustSimStruct,
    RustSimTypeArray,
    RustSimTypeBottom,
    RustSimTypeFunction,
    RustSimTypeInt,
    RustSimTypeOption,
    RustSimTypeReference,
    RustSimTypeResult,
    RustSimTypeSize,
    RustSimTypeSlice,
    RustSimTypeStrRef,
    RustSimTypeUnit,
    RustSimTypeVec,
    is_composite_type,
)
from angr.rust.typehoon.translator import RustTypeTranslator
from angr.sim_type import SimTypeArray, SimTypeFunction, SimTypeLongLong


def _blank_type_db_loader() -> TypeDBLoader:
    project = angr.load_shellcode(b"\x90", arch="amd64")
    loader = object.__new__(TypeDBLoader)
    loader.project = project
    loader.kb = project.kb
    loader._struct_db = {}
    loader._prototype_db = {}
    loader._pending_types = set()
    return loader


class TestRustSimType(unittest.TestCase):
    def test_prototype_copy_preserves_args(self):
        # Function.prototype's setter copies prototypes; copy() must not rebuild or lose the argument types
        arch = archinfo.ArchAMD64()
        u64 = RustSimTypeInt(64, signed=False)
        ok_ty = RustSimStruct(OrderedDict({"field_0": u64}), name="struct8", pack=True)
        err_ty = RustSimStruct(OrderedDict({"field_0": u64}), name="struct16", pack=True)
        ref = RustSimTypeReference(RustSimTypeResult(ok_ty, 0, 8, err_ty, 1, 8))

        prototype = RustSimTypeFunction([ref, u64], None, is_arg0_retbuf=True)
        assert prototype.copy().args[0] is ref

        # every type entering the type solver has to be translatable
        RustTypeTranslator(arch).simtype2tc(prototype.copy().args[0])

    def test_rust_retbuf_function_normalization(self):
        field_ty = RustSimTypeInt(64, signed=False)
        ret_ty = RustSimStruct(OrderedDict({"field_0": field_ty}), name="Ret", pack=True)
        prototype = RustSimTypeFunction(
            [RustSimTypeReference(ret_ty), field_ty],
            None,
            is_arg0_retbuf=True,
        )

        normalized = prototype.normalize()

        assert is_composite_type(ret_ty)
        assert normalized.returnty == ret_ty
        assert tuple(normalized.args) == (field_ty,)
        assert normalized.is_arg0_retbuf is False
        assert prototype.normalize() is not prototype

    def test_rust_scalar_reference_and_array_repr_json_roundtrip(self):
        arch = archinfo.ArchAMD64()
        u32 = RustSimTypeInt(32, signed=False, label="len")

        assert repr(u32) == "u32"
        assert u32.repr("n") == "n: u32"
        assert RustSimTypeInt.from_json(u32.to_json()).label == "len"

        usize = RustSimTypeSize(signed=False)
        assert usize.size(arch) == 64
        assert repr(usize) == "usize"
        assert RustSimTypeSize.from_json(usize.to_json()).signed is False
        assert usize.copy().size(arch) == 64

        bottom_ref = RustSimTypeReference(RustSimTypeBottom())
        assert bottom_ref.repr("ptr") == "*u8 ptr"

        ref = RustSimTypeReference(u32, label="r", offset=4)
        assert ref.size(arch) == 64
        assert ref.repr("arg") == "arg: &u32"
        assert ref.copy().offset == 4

        array = RustSimTypeArray(u32, length=3, label="arr")
        assert repr(array) == "[u32; 3]"
        assert array.repr("items") == "items: [u32; 3]"
        assert array.copy().length == 3

        fn = RustSimTypeFunction([ref, u32], u32, arg_names=["self", "n"], variadic=True)
        assert "..." in repr(fn)
        assert "..." in fn._repr("callee", full=1)
        assert '"self"' in fn._arg_names_str()
        assert fn.to_json()["variadic"] is True

    def test_rust_int_equality_includes_size(self):
        # regression test for angr/angr#6625: ints of different sizes compared equal (and hashed equal), which made
        # the declared type of unified variables depend on nondeterministic set iteration order
        arch = archinfo.ArchAMD64()
        u8 = RustSimTypeInt(8, signed=False)
        u32 = RustSimTypeInt(32, signed=False)
        u64 = RustSimTypeInt(64, signed=False)

        assert u32 != u64
        assert u8 != u32
        assert hash(u32) != hash(u64)
        assert u32 == RustSimTypeInt(32, signed=False)
        assert hash(u32) == hash(RustSimTypeInt(32, signed=False))
        assert u32 != RustSimTypeInt(32, signed=True)

        # copy() must preserve the explicit size
        assert u64.copy().size(arch) == 64
        assert u64.copy() == u64

    def test_rust_struct_nested_field_lookup_and_json_roundtrip(self):
        arch = archinfo.ArchAMD64()
        inner = RustSimStruct(OrderedDict({"value": RustSimTypeInt(16, signed=False)}), name="Inner", pack=True)
        outer = RustSimStruct(
            OrderedDict({"inner": inner, "tail": RustSimTypeInt(32, signed=False)}), name="Outer", pack=True
        )

        inner_value_ty = outer.get_field_ty("inner.value")
        assert inner_value_ty is not None
        assert inner_value_ty.size(arch) == 16
        assert outer.get_field_offset("inner.value", arch) == 0
        assert outer.get_field_offset("missing", arch, default=-1) == -1
        assert "struct Outer" in outer.repr(full=2)

        data = outer.to_json()
        data["_size"] = outer.size(arch)
        restored = RustSimStruct.from_json(data)
        assert restored.name == "Outer"
        assert restored._size == outer.size(arch)

    def test_rust_enum_result_option_discriminants_and_json_roundtrip(self):
        arch = archinfo.ArchAMD64()
        ok_ty = RustSimTypeInt(64, signed=False)
        err_ty = RustSimTypeInt(16, signed=False)

        result_ty = RustSimTypeResult(ok_ty, 0, 0, err_ty, -(1 << 15), 2)
        err_variant = result_ty.get_variant(1 << 15)
        assert err_variant is not None
        assert err_variant.name == "Err"
        assert RustSimTypeResult.from_json(result_ty.to_json()).name.startswith("Result<")

        option_ty = RustSimTypeOption(0, 1, ok_ty, 1, 1)
        none_variant = option_ty.get_variant(0)
        assert none_variant is not None
        assert none_variant.name == "None"
        assert RustSimTypeOption.from_json(option_ty.to_json()).name.startswith("Option<")

        none = EnumVariant.from_no_data("None", 0, 1)
        some = EnumVariant.from_single_field_ty("Some", ok_ty, 1, 1)
        enum_ty = RustSimEnum("OptionLike", [none, some])
        some_variant = enum_ty.get_variant_by_name("Some")
        assert some_variant is not None
        assert some_variant.name == "Some"
        assert enum_ty.num_variants() == 2
        assert RustSimEnum.from_json(enum_ty.to_json()).name == "OptionLike"

        assert some.has_fields()
        assert some.first_field_offset(arch) >= 1
        assert some.size(arch) == some.bits(arch) // 8
        assert some.as_struct_ty().fields["discriminant"].size(arch) == 8
        assert EnumVariant.from_json(some.to_json()) == some

    def test_rust_slice_layout_uses_two_machine_words(self):
        arch = archinfo.ArchAMD64()
        slice_ty = RustSimTypeSlice(RustSimTypeInt(8, signed=False))

        assert slice_ty.size(arch) == 128
        assert list(slice_ty.fields) == ["data_ptr", "length"]
        assert slice_ty.repr("s") == "s: &[u8]"

        vec_ty = RustSimTypeVec(RustSimTypeInt(16, signed=False), order=("ptr", "len", "cap"))
        assert repr(vec_ty) == "Vec<u16>"
        assert list(vec_ty.fields) == ["ptr", "len", "cap"]
        assert RustSimTypeVec.from_json(vec_ty.to_json()).order == ("ptr", "len", "cap")

        unit_ty = RustSimTypeUnit()
        assert unit_ty.size(arch) == 0
        assert unit_ty.copy().name == "()"
        assert RustSimTypeUnit.from_json(unit_ty.to_json()).name == "()"

        strref_ty = RustSimTypeStrRef()
        assert repr(strref_ty) == "&str"
        assert strref_ty.copy().name == "&str"
        assert RustSimTypeStrRef.from_json(strref_ty.to_json()).name == "&str"

    def test_rust_type_translator_handles_rust_simtypes_and_type_constants(self):
        arch = archinfo.ArchAMD64()
        translator = RustTypeTranslator(arch)

        struct_tc = typeconsts.Struct(
            fields={0: typeconsts.Int16(), 4: typeconsts.Pointer64(typeconsts.Int8())},
            field_names={0: "tag", 4: "ptr"},
            name="Pair",
        )
        struct_ty, has_nonexistent_ref = translator.tc2simtype(struct_tc)
        assert has_nonexistent_ref is False
        assert isinstance(struct_ty, RustSimStruct)
        assert struct_ty.name == "Pair"
        assert list(struct_ty.fields) == ["tag", "ptr"]
        assert isinstance(struct_ty.fields["tag"], RustSimTypeInt)
        assert struct_ty.fields["tag"].size(arch) == 16
        assert isinstance(struct_ty.fields["ptr"], RustSimTypeReference)

        array_ty, has_nonexistent_ref = translator.tc2simtype(typeconsts.Array(typeconsts.Int32(), 2))
        assert has_nonexistent_ref is False
        assert isinstance(array_ty, RustSimTypeArray)
        assert array_ty.length == 2
        assert isinstance(array_ty.elem_type, RustSimTypeInt)
        assert array_ty.elem_type.size(arch) == 32

        result_tc = typeconsts.RustEnum(
            "core::result::Result<u64, u16>",
            [
                typeconsts.EnumVariant("Ok", [(typeconsts.Int64(), "__0")], 0, 1, 8),
                typeconsts.EnumVariant("Err", [(typeconsts.Int16(), "__0")], 1, 1, 2),
            ],
        )
        result_ty, has_nonexistent_ref = translator.tc2simtype(result_tc)
        assert has_nonexistent_ref is False
        assert isinstance(result_ty, RustSimTypeResult)
        assert result_ty.get_variant(0) is not None

        option_tc = typeconsts.RustEnum(
            "core::option::Option<u32>",
            [
                typeconsts.EnumVariant("None", [], 0, 1, 0),
                typeconsts.EnumVariant("Some", [(typeconsts.Int32(), "__0")], 1, 1, 4),
            ],
        )
        option_ty, has_nonexistent_ref = translator.tc2simtype(option_tc)
        assert has_nonexistent_ref is False
        assert isinstance(option_ty, RustSimTypeOption)
        assert option_ty.get_variant_by_name("Some") is not None

        lifted_struct = translator.simtype2tc(
            RustSimStruct(OrderedDict({"value": RustSimTypeInt(32, signed=False)}), name="Lifted", pack=True)
        )
        assert isinstance(lifted_struct, typeconsts.Struct)
        assert lifted_struct.field_names == {0: "value"}

        lifted_enum = translator.simtype2tc(
            RustSimEnum(
                "EnumLike",
                [
                    EnumVariant.from_no_data("None", 0, 1),
                    EnumVariant.from_single_field_ty("Some", RustSimTypeInt(8), 1, 1),
                ],
            )
        )
        assert isinstance(lifted_enum, typeconsts.RustEnum)
        assert lifted_enum.get_variant("Some") is not None

    def test_type_db_loader_parses_structs_slices_and_enums(self):
        loader = _blank_type_db_loader()
        arch = loader.project.arch

        bool_ty = loader._parse_type({"kind": "Primitive", "name": "bool", "size": 1})
        assert bool_ty is not None
        assert bool_ty.size(arch) == 8
        assert loader._parse_type({"kind": "Primitive", "name": "f32", "size": 4}) is None

        str_data = {
            "kind": "Struct",
            "name": "&str",
            "fields": {
                "0": ["data_ptr", {"kind": "Pointer", "pts_to": {"kind": "Primitive", "name": "u8", "size": 1}}],
                "8": ["length", {"kind": "Primitive", "name": "usize", "size": 8}],
            },
        }
        str_ty = loader._parse_type(str_data)
        assert isinstance(str_ty, RustSimTypeStrRef)

        vec_data = {
            "kind": "Struct",
            "name": "Vec2",
            "fields": {
                "0": [
                    "items",
                    {"kind": "Array", "ele_type": {"kind": "Primitive", "name": "u16", "size": 2}, "length": 2},
                ]
            },
        }
        vec_ty = loader._parse_type(vec_data)
        assert isinstance(vec_ty, RustSimStruct)
        assert isinstance(vec_ty.fields["items"], RustSimTypeArray)

        option_ty = loader._parse_type(
            {
                "kind": "Enumeration",
                "name": "core::option::Option<u32>",
                "discriminant_size": 1,
                "variants": {
                    "None": [0, []],
                    "Some": [1, [["__0", {"kind": "Primitive", "name": "u32", "size": 4}]]],
                },
            }
        )
        assert isinstance(option_ty, RustSimTypeOption)

        result_ty = loader._parse_type(
            {
                "kind": "Enumeration",
                "name": "core::result::Result<u64, u16>",
                "discriminant_size": 1,
                "variants": {
                    "Ok": [0, [["__0", {"kind": "Primitive", "name": "u64", "size": 8}]]],
                    "Err": [1, [["__0", {"kind": "Primitive", "name": "u16", "size": 2}]]],
                },
            }
        )
        assert isinstance(result_ty, RustSimTypeResult)

    def test_type_db_loader_fits_and_negotiates_large_abi_types(self):
        loader = _blank_type_db_loader()
        large_struct = RustSimStruct(
            OrderedDict(
                {
                    "a": RustSimTypeInt(64, signed=False),
                    "b": RustSimTypeInt(64, signed=False),
                    "c": RustSimTypeInt(64, signed=False),
                }
            ),
            name="Large",
            pack=True,
        )

        direct_arg = loader._fit_abi(RustSimTypeFunction([large_struct], RustSimTypeInt(32, signed=False)))
        assert isinstance(direct_arg.args[0], RustSimTypeReference)
        assert direct_arg.returnty is not None

        retbuf = loader._fit_abi(RustSimTypeFunction([], large_struct))
        assert retbuf.returnty is None
        assert retbuf.is_arg0_retbuf is True
        assert isinstance(retbuf.args[0], RustSimTypeReference)

        two_word_struct = RustSimStruct(
            OrderedDict({"a": RustSimTypeInt(64, signed=False), "b": RustSimTypeInt(64, signed=False)}),
            name="Pair",
            pack=True,
        )
        rust_proto = RustSimTypeFunction([], two_word_struct)
        old_direct = SimTypeFunction([], SimTypeArray(SimTypeLongLong(signed=False), 2))
        assert loader._negotiate_prototype(rust_proto, old_direct) is rust_proto


if __name__ == "__main__":
    unittest.main()
