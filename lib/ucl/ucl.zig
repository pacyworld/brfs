const std = @import("std");
const c = @cImport({
    @cInclude("ucl.h");
});

pub const ObjectType = enum(c_int) {
    object = c.UCL_OBJECT,
    array = c.UCL_ARRAY,
    int_ = c.UCL_INT,
    float_ = c.UCL_FLOAT,
    string = c.UCL_STRING,
    boolean = c.UCL_BOOLEAN,
    time = c.UCL_TIME,
    userdata = c.UCL_USERDATA,
    null_ = c.UCL_NULL,
};

pub const Object = struct {
    ptr: *const c.ucl_object_t,

    pub fn objectType(self: Object) ObjectType {
        return @enumFromInt(c.ucl_object_type(self.ptr));
    }

    pub fn key(self: Object) ?[]const u8 {
        const k = c.ucl_object_key(self.ptr);
        if (k == null) return null;
        return std.mem.span(k);
    }

    pub fn toString(self: Object) ?[]const u8 {
        const s = c.ucl_object_tostring(self.ptr);
        if (s == null) return null;
        return std.mem.span(s);
    }

    pub fn toInt(self: Object) i64 {
        return c.ucl_object_toint(self.ptr);
    }

    pub fn toBool(self: Object) bool {
        return c.ucl_object_toboolean(self.ptr);
    }

    pub fn lookup(self: Object, name: [*:0]const u8) ?Object {
        const obj = c.ucl_object_lookup(self.ptr, name);
        if (obj == null) return null;
        return Object{ .ptr = obj };
    }

    pub fn iterate(self: Object) Iterator {
        return Iterator{ .obj = self.ptr, .iter = null };
    }
};

pub const Iterator = struct {
    obj: *const c.ucl_object_t,
    iter: ?*c.ucl_object_iter_t,

    pub fn next(self: *Iterator) ?Object {
        const result = c.ucl_object_iterate_with_error(
            self.obj,
            @ptrCast(&self.iter),
            true,
            null,
        );
        if (result == null) return null;
        return Object{ .ptr = result };
    }
};

pub const Parser = struct {
    ptr: *c.struct_ucl_parser,

    pub fn init(flags: c_int) ?Parser {
        const p = c.ucl_parser_new(flags) orelse return null;
        return Parser{ .ptr = p };
    }

    pub fn deinit(self: Parser) void {
        c.ucl_parser_free(self.ptr);
    }

    pub fn addFile(self: Parser, filename: [*:0]const u8) bool {
        return c.ucl_parser_add_file(self.ptr, filename);
    }

    pub fn addString(self: Parser, data: []const u8) bool {
        return c.ucl_parser_add_string(self.ptr, data.ptr, data.len);
    }

    pub fn getObject(self: Parser) ?Object {
        const obj = c.ucl_parser_get_object(self.ptr);
        if (obj == null) return null;
        return Object{ .ptr = obj };
    }

    pub fn getError(self: Parser) ?[]const u8 {
        const err = c.ucl_parser_get_error(self.ptr);
        if (err == null) return null;
        return std.mem.span(err);
    }
};

pub fn unref(obj: Object) void {
    c.ucl_object_unref(@constCast(obj.ptr));
}
