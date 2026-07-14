#include <ruby.h>

#include "datadog_ruby_common.h"
#include "otel_thread_ctx.h"

// This binding is Linux-only: the underlying libdatadog crate is gated on
// `target_os = "linux"` (it relies on the TLSDESC TLS dialect so an
// out-of-process eBPF profiler can read the record), so the header/symbols
// are absent on other platforms. `HAVE_DATADOG_OTEL_THREAD_CTX_H` is set by
// `have_header` in extconf.rb.
#ifdef HAVE_DATADOG_OTEL_THREAD_CTX_H
#include <datadog/otel-thread-ctx.h>
#endif

static VALUE native_set(VALUE _self, VALUE trace_id, VALUE span_id, VALUE local_root_span_id);
static VALUE native_detach_and_free(VALUE _self);
static VALUE native_supported_p(VALUE _self);
static VALUE native_debug_peek(VALUE _self);

void otel_thread_ctx_init(VALUE core_module) {
  VALUE otel_thread_ctx_module = rb_define_module_under(core_module, "OTelThreadContext");

  rb_define_singleton_method(otel_thread_ctx_module, "_native_set", native_set, 3);
  rb_define_singleton_method(otel_thread_ctx_module, "_native_detach_and_free", native_detach_and_free, 0);
  rb_define_singleton_method(otel_thread_ctx_module, "_native_supported?", native_supported_p, 0);
  rb_define_singleton_method(otel_thread_ctx_module, "_native_debug_peek", native_debug_peek, 0);
}

#ifdef HAVE_DATADOG_OTEL_THREAD_CTX_H

// trace_id is expected to fit in 16 bytes (<= 128-bit), span_id and
// local_root_span_id in 8 bytes each (<= 64-bit).
static void pack_id_big_endian(VALUE id, uint8_t *buffer, size_t size) {
  rb_integer_pack(id, buffer, size, 1, 0, INTEGER_PACK_MSWORD_FIRST | INTEGER_PACK_BIG_ENDIAN);
}

static VALUE native_set(DDTRACE_UNUSED VALUE _self, VALUE trace_id, VALUE span_id, VALUE local_root_span_id) {
  uint8_t trace_id_bytes[16] = {0};
  uint8_t span_id_bytes[8] = {0};
  uint8_t local_root_span_id_bytes[8] = {0};

  pack_id_big_endian(trace_id, trace_id_bytes, sizeof(trace_id_bytes));
  pack_id_big_endian(span_id, span_id_bytes, sizeof(span_id_bytes));
  pack_id_big_endian(local_root_span_id, local_root_span_id_bytes, sizeof(local_root_span_id_bytes));

  ddog_otel_thread_ctx_update(&trace_id_bytes, &span_id_bytes, &local_root_span_id_bytes);

  return Qtrue;
}

// Detaches the thread context record currently attached to the calling
// thread (if any) and frees it.
static VALUE native_detach_and_free(VALUE _self) {
  struct ddog_ThreadContextHandle *ctx = ddog_otel_thread_ctx_detach();

  if (ctx) ddog_otel_thread_ctx_free(ctx);

  return Qtrue;
}

static VALUE native_supported_p(VALUE _self) {
  return Qtrue;
}

// Decodes the packed `attrs_data` blob into a Hash. Each entry is a 1-byte key
// index, a 1-byte value length, then that many value bytes.
static VALUE decode_attrs(const uint8_t *data, uint16_t size) {
  VALUE attrs = rb_hash_new();

  uint16_t offset = 0;
  while (offset + 2 <= size) {
    uint8_t key_index = data[offset];
    uint8_t value_len = data[offset + 1];

    if (offset + 2 + value_len > size) break;

    VALUE value = rb_str_new((const char *) (data + offset + 2), value_len);

    rb_hash_aset(attrs, INT2FIX(key_index), value);
    offset += 2 + value_len;
  }

  return attrs;
}

// Debug-only helper: reads back the record currently attached to the calling
// thread, without disturbing it (detach, read, re-attach). Returns nil if no
// context is attached.
//
// There is no libdatadog API to read a record's fields -- the whole point of
// this feature is that an out-of-process reader (the eBPF profiler) parses the
// raw bytes directly. We do the same here, using the documented, stable wire
// layout (see the `ThreadContextRecord` doc comment in
// `libdd-otel-thread-ctx/src/lib.rs`): trace_id at offset 0 (16 bytes), span_id
// at offset 16 (8 bytes), valid at offset 24 (1 byte), attrs_data_size at
// offset 26 (2 bytes, little-endian), attrs_data at offset 28.
static VALUE native_debug_peek(VALUE _self) {
  struct ddog_ThreadContextHandle *ctx = ddog_otel_thread_ctx_detach();

  if (!ctx) return Qnil;

  const uint8_t *raw = (const uint8_t *) ctx;

  VALUE trace_id = rb_str_new((const char *) raw, 16);
  VALUE span_id = rb_str_new((const char *) (raw + 16), 8);
  VALUE valid = raw[24] ? Qtrue : Qfalse;
  uint16_t attrs_data_size = (uint16_t) raw[26] | ((uint16_t) raw[27] << 8);
  VALUE attrs = decode_attrs(raw + 28, attrs_data_size);

  // Must return NULL: we just detached the only attached context, and nothing else touches
  // this thread's slot in between.
  struct ddog_ThreadContextHandle *previous = ddog_otel_thread_ctx_attach(ctx);
  if (previous) raise_error(rb_eRuntimeError, "Internal: unexpected context already attached during debug_peek");

  VALUE result = rb_hash_new();
  rb_hash_aset(result, ID2SYM(rb_intern("trace_id")), trace_id);
  rb_hash_aset(result, ID2SYM(rb_intern("span_id")), span_id);
  rb_hash_aset(result, ID2SYM(rb_intern("valid")), valid);
  rb_hash_aset(result, ID2SYM(rb_intern("attrs")), attrs);

  return result;
}

#else

static VALUE native_set(DDTRACE_UNUSED VALUE _self, DDTRACE_UNUSED VALUE trace_id, DDTRACE_UNUSED VALUE span_id, DDTRACE_UNUSED VALUE local_root_span_id) {
  return Qfalse;
}

static VALUE native_detach_and_free(VALUE _self) {
  return Qfalse;
}

static VALUE native_supported_p(VALUE _self) {
  return Qfalse;
}

static VALUE native_debug_peek(VALUE _self) {
  return Qnil;
}

#endif
