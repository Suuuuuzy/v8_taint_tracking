// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_SOURCE_POSITION_TABLE_H_
#define V8_SOURCE_POSITION_TABLE_H_

#include "src/assert-scope.h"
#include "src/checks.h"
#include "src/handles.h"
#include "src/zone-containers.h"
#include "src/frames.h"

namespace v8 {
namespace internal {

class AbstractCode;
class BytecodeArray;
class ByteArray;
class Isolate;
class Zone;

struct PositionTableEntry {
  PositionTableEntry()
    : code_offset(0), source_position(0), is_statement(false),
      ast_taint_tracking_index(-1) {}
  PositionTableEntry(int offset, int source, bool statement,
                     int ast_taint_tracking_index)
    : code_offset(offset), source_position(source), is_statement(statement),
      ast_taint_tracking_index(ast_taint_tracking_index) {}

  int code_offset;
  int source_position;
  bool is_statement;
  int ast_taint_tracking_index;
};

class SourcePositionTableBuilder {
 public:
  enum RecordingMode { OMIT_SOURCE_POSITIONS, RECORD_SOURCE_POSITIONS };

  SourcePositionTableBuilder(Isolate* isolate, Zone* zone,
                             RecordingMode mode = RECORD_SOURCE_POSITIONS);

  void EndJitLogging(AbstractCode* code);

  static constexpr int NO_TAINT_TRACKING_INDEX =
    v8::internal::StackFrame::TaintStackFrameInfo::UNINSTRUMENTED;

  void AddPosition(size_t code_offset, int source_position, bool is_statement,
                   int ast_taint_tracking_index);
  Handle<ByteArray> ToSourcePositionTable();

 private:
  void AddEntry(const PositionTableEntry& entry);

  inline bool Omit() const { return mode_ == OMIT_SOURCE_POSITIONS; }

  Isolate* isolate_;
  RecordingMode mode_;
  ZoneVector<byte> bytes_;
#ifdef ENABLE_SLOW_DCHECKS
  ZoneVector<PositionTableEntry> raw_entries_;
#endif
  PositionTableEntry previous_;  // Previously written entry, to compute delta.
  // Currently jit_handler_data_ is used to store JITHandler-specific data
  // over the lifetime of a SourcePositionTableBuilder.
  void* jit_handler_data_;
};

class SourcePositionTableIterator {
 public:
  explicit SourcePositionTableIterator(ByteArray* byte_array);

  void Advance();

  int code_offset() const {
    DCHECK(!done());
    return current_.code_offset;
  }
  int source_position() const {
    DCHECK(!done());
    return current_.source_position;
  }
  bool is_statement() const {
    DCHECK(!done());
    return current_.is_statement;
  }
  int ast_taint_tracking_index() const {
    DCHECK(!done());
    return current_.ast_taint_tracking_index;
  }
  bool done() const { return index_ == kDone; }

 private:
  static const int kDone = -1;

  ByteArray* table_;
  int index_;
  PositionTableEntry current_;
  DisallowHeapAllocation no_gc;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_SOURCE_POSITION_TABLE_H_
