// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTERPRETER_BYTECODE_PIPELINE_H_
#define V8_INTERPRETER_BYTECODE_PIPELINE_H_

#include "src/interpreter/bytecode-register-allocator.h"
#include "src/interpreter/bytecode-register.h"
#include "src/interpreter/bytecodes.h"
#include "src/objects.h"
#include "src/zone-containers.h"

namespace v8 {
namespace internal {
namespace interpreter {

class BytecodeLabel;
class BytecodeNode;
class BytecodeSourceInfo;

// Interface for bytecode pipeline stages.
class BytecodePipelineStage {
 public:
  virtual ~BytecodePipelineStage() {}

  // Write bytecode node |node| into pipeline. The node is only valid
  // for the duration of the call. Callee's should clone it if
  // deferring Write() to the next stage.
  virtual void Write(BytecodeNode* node) = 0;

  // Write jump bytecode node |node| which jumps to |label| into pipeline.
  // The node and label are only valid for the duration of the call. This call
  // implicitly ends the current basic block so should always write to the next
  // stage.
  virtual void WriteJump(BytecodeNode* node, BytecodeLabel* label) = 0;

  // Binds |label| to the current bytecode location. This call implicitly
  // ends the current basic block and so any deferred bytecodes should be
  // written to the next stage.
  virtual void BindLabel(BytecodeLabel* label) = 0;

  // Binds |label| to the location of |target|. This call implicitly
  // ends the current basic block and so any deferred bytecodes should be
  // written to the next stage.
  virtual void BindLabel(const BytecodeLabel& target, BytecodeLabel* label) = 0;

  // Flush the pipeline and generate a bytecode array.
  virtual Handle<BytecodeArray> ToBytecodeArray(
      int fixed_register_count, int parameter_count,
      Handle<FixedArray> handler_table) = 0;
};

// Source code position information.
class BytecodeSourceInfo final {
 public:
  static const int kUninitializedPosition = -1;

  BytecodeSourceInfo()
      : position_type_(PositionType::kNone),
        source_position_(kUninitializedPosition),
        ast_taint_tracking_index_(-1) {}

  BytecodeSourceInfo(int source_position, bool is_statement,
                     int ast_taint_tracking_index)
      : position_type_(is_statement ? PositionType::kStatement
                                    : PositionType::kExpression),
        source_position_(source_position),
        ast_taint_tracking_index_(ast_taint_tracking_index) {
    DCHECK_GE(source_position, 0);
  }

  // Makes instance into a statement position.
  void MakeStatementPosition(int source_position,
                             int ast_taint_tracking_index) {
    // Statement positions can be replaced by other statement
    // positions. For example , "for (x = 0; x < 3; ++x) 7;" has a
    // statement position associated with 7 but no bytecode associated
    // with it. Then Next is emitted after the body and has
    // statement position and overrides the existing one.
    position_type_ = PositionType::kStatement;
    source_position_ = source_position;
    ast_taint_tracking_index_ = ast_taint_tracking_index;
  }

  // Makes instance into an expression position. Instance should not
  // be a statement position otherwise it could be lost and impair the
  // debugging experience.
  void MakeExpressionPosition(int source_position,
                              int ast_taint_tracking_index) {
    DCHECK(!is_statement());
    position_type_ = PositionType::kExpression;
    source_position_ = source_position;
    ast_taint_tracking_index_ = ast_taint_tracking_index;
  }

  // Forces an instance into an expression position.
  void ForceExpressionPosition(int source_position,
                               int ast_taint_tracking_index) {
    position_type_ = PositionType::kExpression;
    source_position_ = source_position;
    ast_taint_tracking_index_ = ast_taint_tracking_index;
  }

  // Clones a source position. The current instance is expected to be
  // invalid.
  void Clone(const BytecodeSourceInfo& other) {
    DCHECK(!is_valid());
    position_type_ = other.position_type_;
    source_position_ = other.source_position_;
    ast_taint_tracking_index_ = other.ast_taint_tracking_index_;
  }

  int source_position() const {
    DCHECK(is_valid());
    return source_position_;
  }

  bool is_statement() const {
    return position_type_ == PositionType::kStatement;
  }
  bool is_expression() const {
    return position_type_ == PositionType::kExpression;
  }

  int ast_taint_tracking_index() const {
    return ast_taint_tracking_index_;
  }

  bool is_valid() const { return position_type_ != PositionType::kNone; }
  void set_invalid() {
    position_type_ = PositionType::kNone;
    source_position_ = kUninitializedPosition;
  }

  bool operator==(const BytecodeSourceInfo& other) const {
    return position_type_ == other.position_type_ &&
           source_position_ == other.source_position_;
  }

  bool operator!=(const BytecodeSourceInfo& other) const {
    return position_type_ != other.position_type_ ||
           source_position_ != other.source_position_;
  }

 private:
  enum class PositionType : uint8_t { kNone, kExpression, kStatement };

  PositionType position_type_;
  int source_position_;
  int ast_taint_tracking_index_;

  DISALLOW_COPY_AND_ASSIGN(BytecodeSourceInfo);
};

// A container for a generated bytecode, it's operands, and source information.
// These must be allocated by a BytecodeNodeAllocator instance.
class BytecodeNode final : ZoneObject {
 public:
  explicit BytecodeNode(Bytecode bytecode = Bytecode::kIllegal);
  BytecodeNode(Bytecode bytecode, uint32_t operand0);
  BytecodeNode(Bytecode bytecode, uint32_t operand0, uint32_t operand1);
  BytecodeNode(Bytecode bytecode, uint32_t operand0, uint32_t operand1,
               uint32_t operand2);
  BytecodeNode(Bytecode bytecode, uint32_t operand0, uint32_t operand1,
               uint32_t operand2, uint32_t operand3);

  BytecodeNode(const BytecodeNode& other);
  BytecodeNode& operator=(const BytecodeNode& other);

  // Replace the bytecode of this node with |bytecode| and keep the operands.
  void replace_bytecode(Bytecode bytecode) {
    DCHECK_EQ(Bytecodes::NumberOfOperands(bytecode_),
              Bytecodes::NumberOfOperands(bytecode));
    bytecode_ = bytecode;
  }
  void set_bytecode(Bytecode bytecode) {
    DCHECK_EQ(Bytecodes::NumberOfOperands(bytecode), 0);
    bytecode_ = bytecode;
  }
  void set_bytecode(Bytecode bytecode, uint32_t operand0) {
    DCHECK_EQ(Bytecodes::NumberOfOperands(bytecode), 1);
    bytecode_ = bytecode;
    operands_[0] = operand0;
  }
  void set_bytecode(Bytecode bytecode, uint32_t operand0, uint32_t operand1) {
    DCHECK_EQ(Bytecodes::NumberOfOperands(bytecode), 2);
    bytecode_ = bytecode;
    operands_[0] = operand0;
    operands_[1] = operand1;
  }

  // Clone |other|.
  void Clone(const BytecodeNode* const other);

  // Print to stream |os|.
  void Print(std::ostream& os) const;

  // Transform to a node representing |new_bytecode| which has one
  // operand more than the current bytecode.
  void Transform(Bytecode new_bytecode, uint32_t extra_operand);

  Bytecode bytecode() const { return bytecode_; }

  uint32_t operand(int i) const {
    DCHECK_LT(i, operand_count());
    return operands_[i];
  }
  uint32_t* operands() { return operands_; }
  const uint32_t* operands() const { return operands_; }

  int operand_count() const { return Bytecodes::NumberOfOperands(bytecode_); }

  const BytecodeSourceInfo& source_info() const { return source_info_; }
  BytecodeSourceInfo& source_info() { return source_info_; }

  bool operator==(const BytecodeNode& other) const;
  bool operator!=(const BytecodeNode& other) const { return !(*this == other); }

 private:
  static const int kInvalidPosition = kMinInt;

  Bytecode bytecode_;
  uint32_t operands_[Bytecodes::kMaxOperands];
  BytecodeSourceInfo source_info_;
};

std::ostream& operator<<(std::ostream& os, const BytecodeSourceInfo& info);
std::ostream& operator<<(std::ostream& os, const BytecodeNode& node);

}  // namespace interpreter
}  // namespace internal
}  // namespace v8

#endif  // V8_INTERPRETER_BYTECODE_PIPELINE_H_
