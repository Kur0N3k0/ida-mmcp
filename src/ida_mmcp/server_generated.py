# NOTE: This file has been automatically generated, do not modify!
# Architecture based on https://github.com/mrexodia/ida-pro-mcp (MIT License)
import sys
if sys.version_info >= (3, 12):
    from typing import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired
else:
    from typing_extensions import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired
from pydantic import Field

T = TypeVar("T")

class Metadata(TypedDict):
    path: str
    module: str
    base: str
    size: str
    md5: str
    sha256: str
    crc32: str
    filesize: str

class Function(TypedDict):
    address: str
    name: str
    size: str

class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str

class Page(TypedDict, Generic[T]):
    data: list[T]
    next_offset: Optional[int]

class Global(TypedDict):
    address: str
    name: str

class Import(TypedDict):
    address: str
    imported_name: str
    module: str

class String(TypedDict):
    address: str
    length: int
    string: str

class DisassemblyLine(TypedDict):
    segment: NotRequired[str]
    address: str
    label: NotRequired[str]
    instruction: str
    comments: NotRequired[list[str]]

class Argument(TypedDict):
    name: str
    type: str

class DisassemblyFunction(TypedDict):
    name: str
    start_ea: str
    return_type: NotRequired[str]
    arguments: NotRequired[list[Argument]]
    stack_frame: list[dict]
    lines: list[DisassemblyLine]

class Xref(TypedDict):
    address: str
    type: str
    function: Optional[Function]

class StackFrameVariable(TypedDict):
    name: str
    offset: str
    size: str
    type: str

class StructureMember(TypedDict):
    name: str
    offset: str
    size: str
    type: str

class StructureDefinition(TypedDict):
    name: str
    size: str
    members: list[StructureMember]

@mcp.tool()
def get_metadata() -> Metadata:
    """Get metadata about the current IDB"""
    return proxy_call('get_metadata')

@mcp.tool()
def get_function_by_name(name: Annotated[str, Field(description='Name of the function to get')]) -> Function:
    """Get a function by its name"""
    return proxy_call('get_function_by_name', params={"name": name})

@mcp.tool()
def get_function_by_address(address: Annotated[str, Field(description='Address of the function to get')]) -> Function:
    """Get a function by its address"""
    return proxy_call('get_function_by_address', params={"address": address})

@mcp.tool()
def get_current_address() -> str:
    """Get the address currently selected by the user"""
    return proxy_call('get_current_address')

@mcp.tool()
def get_current_function() -> Optional[Function]:
    """Get the function currently selected by the user"""
    return proxy_call('get_current_function')

@mcp.tool()
def convert_number(text: Annotated[str, Field(description='Textual representation of the number to convert')], size: Annotated[Optional[int], Field(description='Size of the variable in bytes')]) -> ConvertedNumber:
    """Convert a number (decimal, hexadecimal) to different representations"""
    return proxy_call('convert_number', params={"text": text, "size": size})

@mcp.tool()
def list_functions(offset: Annotated[int, Field(description='Offset to start listing from (start at 0)')], count: Annotated[int, Field(description='Number of functions to list (100 is a good default, 0 means remainder)')]) -> Page[Function]:
    """List all functions in the database (paginated)"""
    return proxy_call('list_functions', params={"offset": offset, "count": count})

@mcp.tool()
def list_globals_filter(offset: Annotated[int, Field(description='Offset to start listing from (start at 0)')], count: Annotated[int, Field(description='Number of globals to list (100 is a good default, 0 means remainder)')], filter: Annotated[str, Field(description='Filter to apply to the list (required parameter, empty string for no filter). Case-insensitive contains or /regex/ syntax')]) -> Page[Global]:
    """List matching globals in the database (paginated, filtered)"""
    return proxy_call('list_globals_filter', params={"offset": offset, "count": count, "filter": filter})

@mcp.tool()
def list_globals(offset: Annotated[int, Field(description='Offset to start listing from (start at 0)')], count: Annotated[int, Field(description='Number of globals to list (100 is a good default, 0 means remainder)')]) -> Page[Global]:
    """List all globals in the database (paginated)"""
    return proxy_call('list_globals', params={"offset": offset, "count": count})

@mcp.tool()
def list_imports(offset: Annotated[int, Field(description='Offset to start listing from (start at 0)')], count: Annotated[int, Field(description='Number of imports to list (100 is a good default, 0 means remainder)')]) -> Page[Import]:
    """ List all imported symbols with their name and module (paginated) """
    return proxy_call('list_imports', params={"offset": offset, "count": count})

@mcp.tool()
def list_strings_filter(offset: Annotated[int, Field(description='Offset to start listing from (start at 0)')], count: Annotated[int, Field(description='Number of strings to list (100 is a good default, 0 means remainder)')], filter: Annotated[str, Field(description='Filter to apply to the list (required parameter, empty string for no filter). Case-insensitive contains or /regex/ syntax')]) -> Page[String]:
    """List matching strings in the database (paginated, filtered)"""
    return proxy_call('list_strings_filter', params={"offset": offset, "count": count, "filter": filter})

@mcp.tool()
def list_strings(offset: Annotated[int, Field(description='Offset to start listing from (start at 0)')], count: Annotated[int, Field(description='Number of strings to list (100 is a good default, 0 means remainder)')]) -> Page[String]:
    """List all strings in the database (paginated)"""
    return proxy_call('list_strings', params={"offset": offset, "count": count})

@mcp.tool()
def list_local_types():
    """List all Local types in the database"""
    return proxy_call('list_local_types')

@mcp.tool()
def decompile_function(address: Annotated[str, Field(description='Address of the function to decompile')]) -> str:
    """Decompile a function at the given address"""
    return proxy_call('decompile_function', params={"address": address})

@mcp.tool()
def disassemble_function(start_address: Annotated[str, Field(description='Address of the function to disassemble')]) -> DisassemblyFunction:
    """Get assembly code for a function"""
    return proxy_call('disassemble_function', params={"start_address": start_address})

@mcp.tool()
def get_xrefs_to(address: Annotated[str, Field(description='Address to get cross references to')]) -> list[Xref]:
    """Get all cross references to the given address"""
    return proxy_call('get_xrefs_to', params={"address": address})

@mcp.tool()
def get_xrefs_to_field(struct_name: Annotated[str, Field(description='Name of the struct (type) containing the field')], field_name: Annotated[str, Field(description='Name of the field (member) to get xrefs to')]) -> list[Xref]:
    """Get all cross references to a named struct field (member)"""
    return proxy_call('get_xrefs_to_field', params={"struct_name": struct_name, "field_name": field_name})

@mcp.tool()
def get_entry_points() -> list[Function]:
    """Get all entry points in the database"""
    return proxy_call('get_entry_points')

@mcp.tool()
def set_comment(address: Annotated[str, Field(description='Address in the function to set the comment for')], comment: Annotated[str, Field(description='Comment text')]):
    """Set a comment for a given address in the function disassembly and pseudocode"""
    return proxy_call('set_comment', params={"address": address, "comment": comment})

@mcp.tool()
def rename_local_variable(function_address: Annotated[str, Field(description='Address of the function containing the variable')], old_name: Annotated[str, Field(description='Current name of the variable')], new_name: Annotated[str, Field(description='New name for the variable (empty for a default name)')]):
    """Rename a local variable in a function"""
    return proxy_call('rename_local_variable', params={"function_address": function_address, "old_name": old_name, "new_name": new_name})

@mcp.tool()
def rename_global_variable(old_name: Annotated[str, Field(description='Current name of the global variable')], new_name: Annotated[str, Field(description='New name for the global variable (empty for a default name)')]):
    """Rename a global variable"""
    return proxy_call('rename_global_variable', params={"old_name": old_name, "new_name": new_name})

@mcp.tool()
def set_global_variable_type(variable_name: Annotated[str, Field(description='Name of the global variable')], new_type: Annotated[str, Field(description='New type for the variable')]):
    """Set a global variable's type"""
    return proxy_call('set_global_variable_type', params={"variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_global_variable_value_by_name(variable_name: Annotated[str, Field(description='Name of the global variable')]) -> str:
    """
    Read a global variable's value (if known at compile-time)

    Prefer this function over the `data_read_*` functions.
    """
    return proxy_call('get_global_variable_value_by_name', params={"variable_name": variable_name})

@mcp.tool()
def get_global_variable_value_at_address(ea: Annotated[str, Field(description='Address of the global variable')]) -> str:
    """
    Read a global variable's value by its address (if known at compile-time)

    Prefer this function over the `data_read_*` functions.
    """
    return proxy_call('get_global_variable_value_at_address', params={"ea": ea})

@mcp.tool()
def rename_function(function_address: Annotated[str, Field(description='Address of the function to rename')], new_name: Annotated[str, Field(description='New name for the function (empty for a default name)')]):
    """Rename a function"""
    return proxy_call('rename_function', params={"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: Annotated[str, Field(description='Address of the function')], prototype: Annotated[str, Field(description='New function prototype')]):
    """Set a function's prototype"""
    return proxy_call('set_function_prototype', params={"function_address": function_address, "prototype": prototype})

@mcp.tool()
def declare_c_type(c_declaration: Annotated[str, Field(description='C declaration of the type. Examples include: typedef int foo_t; struct bar { int a; bool b; };')]):
    """Create or update a local type from a C declaration"""
    return proxy_call('declare_c_type', params={"c_declaration": c_declaration})

@mcp.tool()
def set_local_variable_type(function_address: Annotated[str, Field(description='Address of the decompiled function containing the variable')], variable_name: Annotated[str, Field(description='Name of the variable')], new_type: Annotated[str, Field(description='New type for the variable')]):
    """Set a local variable's type"""
    return proxy_call('set_local_variable_type', params={"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_stack_frame_variables(function_address: Annotated[str, Field(description='Address of the disassembled function to retrieve the stack frame variables')]) -> list[StackFrameVariable]:
    """ Retrieve the stack frame variables for a given function """
    return proxy_call('get_stack_frame_variables', params={"function_address": function_address})

@mcp.tool()
def get_defined_structures() -> list[StructureDefinition]:
    """ Returns a list of all defined structures """
    return proxy_call('get_defined_structures')

@mcp.tool()
def rename_stack_frame_variable(function_address: Annotated[str, Field(description='Address of the disassembled function to set the stack frame variables')], old_name: Annotated[str, Field(description='Current name of the variable')], new_name: Annotated[str, Field(description='New name for the variable (empty for a default name)')]):
    """ Change the name of a stack variable for an IDA function """
    return proxy_call('rename_stack_frame_variable', params={"function_address": function_address, "old_name": old_name, "new_name": new_name})

@mcp.tool()
def create_stack_frame_variable(function_address: Annotated[str, Field(description='Address of the disassembled function to set the stack frame variables')], offset: Annotated[str, Field(description='Offset of the stack frame variable')], variable_name: Annotated[str, Field(description='Name of the stack variable')], type_name: Annotated[str, Field(description='Type of the stack variable')]):
    """ For a given function, create a stack variable at an offset and with a specific type """
    return proxy_call('create_stack_frame_variable', params={"function_address": function_address, "offset": offset, "variable_name": variable_name, "type_name": type_name})

@mcp.tool()
def set_stack_frame_variable_type(function_address: Annotated[str, Field(description='Address of the disassembled function to set the stack frame variables')], variable_name: Annotated[str, Field(description='Name of the stack variable')], type_name: Annotated[str, Field(description='Type of the stack variable')]):
    """ For a given disassembled function, set the type of a stack variable """
    return proxy_call('set_stack_frame_variable_type', params={"function_address": function_address, "variable_name": variable_name, "type_name": type_name})

@mcp.tool()
def delete_stack_frame_variable(function_address: Annotated[str, Field(description='Address of the function to set the stack frame variables')], variable_name: Annotated[str, Field(description='Name of the stack variable')]):
    """ Delete the named stack variable for a given function """
    return proxy_call('delete_stack_frame_variable', params={"function_address": function_address, "variable_name": variable_name})

@mcp.tool()
def read_memory_bytes(memory_address: Annotated[str, Field(description='Address of the memory value to be read')], size: Annotated[int, Field(description='size of memory to read')]) -> str:
    """
    Read bytes at a given address.

    Only use this function if `get_global_variable_at` and `get_global_variable_by_name`
    both failed.
    """
    return proxy_call('read_memory_bytes', params={"memory_address": memory_address, "size": size})

@mcp.tool()
def data_read_byte(address: Annotated[str, Field(description='Address to get 1 byte value from')]) -> int:
    """
    Read the 1 byte value at the specified address.

    Only use this function if `get_global_variable_at` failed.
    """
    return proxy_call('data_read_byte', params={"address": address})

@mcp.tool()
def data_read_word(address: Annotated[str, Field(description='Address to get 2 bytes value from')]) -> int:
    """
    Read the 2 byte value at the specified address as a WORD.

    Only use this function if `get_global_variable_at` failed.
    """
    return proxy_call('data_read_word', params={"address": address})

@mcp.tool()
def data_read_dword(address: Annotated[str, Field(description='Address to get 4 bytes value from')]) -> int:
    """
    Read the 4 byte value at the specified address as a DWORD.

    Only use this function if `get_global_variable_at` failed.
    """
    return proxy_call('data_read_dword', params={"address": address})

@mcp.tool()
def data_read_qword(address: Annotated[str, Field(description='Address to get 8 bytes value from')]) -> int:
    """
    Read the 8 byte value at the specified address as a QWORD.

    Only use this function if `get_global_variable_at` failed.
    """
    return proxy_call('data_read_qword', params={"address": address})

@mcp.tool()
def data_read_string(address: Annotated[str, Field(description='Address to get string from')]) -> str:
    """
    Read the string at the specified address.

    Only use this function if `get_global_variable_at` failed.
    """
    return proxy_call('data_read_string', params={"address": address})

@mcp.tool()
def dbg_get_registers() -> list[dict[str, str]]:
    """Get all registers and their values. This function is only available when debugging."""
    return proxy_call('dbg_get_registers')

@mcp.tool()
def dbg_get_call_stack() -> list[dict[str, str]]:
    """Get the current call stack."""
    return proxy_call('dbg_get_call_stack')

@mcp.tool()
def dbg_list_breakpoints():
    """List all breakpoints in the program."""
    return proxy_call('dbg_list_breakpoints')

@mcp.tool()
def dbg_start_process() -> str:
    """Start the debugger"""
    return proxy_call('dbg_start_process')

@mcp.tool()
def dbg_exit_process() -> str:
    """Exit the debugger"""
    return proxy_call('dbg_exit_process')

@mcp.tool()
def dbg_continue_process() -> str:
    """Continue the debugger"""
    return proxy_call('dbg_continue_process')

@mcp.tool()
def dbg_run_to(address: Annotated[str, Field(description='Run the debugger to the specified address')]) -> str:
    """Run the debugger to the specified address"""
    return proxy_call('dbg_run_to', params={"address": address})

@mcp.tool()
def dbg_set_breakpoint(address: Annotated[str, Field(description='Set a breakpoint at the specified address')]) -> str:
    """Set a breakpoint at the specified address"""
    return proxy_call('dbg_set_breakpoint', params={"address": address})

@mcp.tool()
def dbg_delete_breakpoint(address: Annotated[str, Field(description='del a breakpoint at the specified address')]) -> str:
    """del a breakpoint at the specified address"""
    return proxy_call('dbg_delete_breakpoint', params={"address": address})

@mcp.tool()
def dbg_enable_breakpoint(address: Annotated[str, Field(description='Enable or disable a breakpoint at the specified address')], enable: Annotated[bool, Field(description='Enable or disable a breakpoint')]) -> str:
    """Enable or disable a breakpoint at the specified address"""
    return proxy_call('dbg_enable_breakpoint', params={"address": address, "enable": enable})

