#ifndef AST_SERIALIZATION_H
#define AST_SERIALIZATION_H


// This file defines how to serialize ASTs to the log file during symbolic
// execution.

#include "src/ast/ast.h"

#include "symbolic_state.h"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <ast.capnp.h>

#include <unordered_map>

namespace tainttracking {


class ConcolicExecutor;
class SymbolicState;
class ExpressionSlot;
class SymbolicStackFrame;



class ObjectOwnPropertiesVisitor {
public:
  Status Visit(v8::internal::Handle<v8::internal::JSReceiver> receiver);

  // Returns true to visit value recursively
  virtual bool VisitKeyValue(
      v8::internal::Handle<v8::internal::String> key,
      v8::internal::Handle<v8::internal::Object> value) = 0;

protected:
  ObjectOwnPropertiesVisitor() {}

private:
  Status ProcessReceiver(
      v8::internal::Handle<v8::internal::JSReceiver> receiver);

  v8::internal::Handle<v8::internal::ArrayList> value_stack_;
  v8::internal::Isolate* isolate_;
};





class BuilderSerializer {
 public:
  Status Serialize(::Ast::NodeLabel::Builder builder, const NodeLabel& label);
  Status Deserialize(::Ast::NodeLabel::Reader node, NodeLabel* label);
};


class SymbolicMemorySlot {
public:
  SymbolicMemorySlot(bool, std::shared_ptr<SymbolicState>);
  SymbolicMemorySlot(const SymbolicMemorySlot& other);

  bool HasSymbolicState() const;
  std::shared_ptr<SymbolicState> GetState() const;

  SymbolicMemorySlot& operator=(const SymbolicMemorySlot& other);

private:
  bool has_symbolic_state_;
  std::shared_ptr<SymbolicState> state_;
  SymbolicMemorySlot() = delete;
};


class SymbolicMemorySlotSerializer {
public:
  SymbolicMemorySlotSerializer(v8::internal::Isolate* isolate);
  ~SymbolicMemorySlotSerializer();

  v8::internal::Handle<v8::internal::Object> Serialize(
      const SymbolicMemorySlot& slot);
  SymbolicMemorySlot* Deserialize(
      v8::internal::Handle<v8::internal::Object> obj);

private:
  SymbolicMemorySlotSerializer();

  GarbageCollectableManager<SymbolicMemorySlot> garbage_;
  v8::internal::Isolate* isolate_;
};

class SymbolicExecutor {
public:
  virtual ~SymbolicExecutor() {}

  // Called after executing the expression when the ExpressionSlot dependencies
  // have symbolic values.
  //
  // Returns the symbolic state for this expression.
  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact,
      ExpressionSlot* owner) {
    UNREACHABLE();
  };

  virtual std::shared_ptr<SymbolicState> StaticValue(
      const SymbolicFactory& fact,
      ExpressionSlot* owner) {
    UNREACHABLE();
  };

  virtual void InitSlot(ExpressionSlot* slot) {}

  virtual std::shared_ptr<SymbolicState> OnAssignmentRValue(
      const SymbolicFactory& fact,
      ExpressionSlot* owner) {
    UNREACHABLE();
  };

  virtual void OnBeforeExecute(ExpressionSlot* slot) {}

  template <typename T, typename Reader>
  static T* New(
      Reader reader,
      std::vector<::Ast::NodeLabel::Reader>* deps);
};

class ExecutionInfo {
public:
  ExecutionInfo(v8::internal::Handle<v8::internal::Object>,
                CheckType type);
  virtual ~ExecutionInfo();

  v8::internal::Handle<v8::internal::Object> GetEval() const;
  CheckType GetCheckType() const;

private:
  ExecutionInfo() = delete;

  v8::internal::Handle<v8::internal::Object> eval_;
  CheckType checktype_;
};

class VariableLoadExecutionInfo : public ExecutionInfo {
public:

  VariableLoadExecutionInfo(
      v8::internal::Handle<v8::internal::Object> eval,
      CheckType type,

      // Might be null if no memory slot was found for example because of an
      // unimplemented symbolic storage or if there was an uninitialized
      // variable
      SymbolicMemorySlot* memslot);
  virtual ~VariableLoadExecutionInfo();

  SymbolicMemorySlot* GetSlot() const;

private:
  VariableLoadExecutionInfo() = delete;
  SymbolicMemorySlot* slot_;
};

typedef KeyValueStruct<SymbolicMemorySlot,
                       SymbolicMemorySlot> SymbolicMemKeyValue;


class ObjectPropertySymbolicStateManager {
public:

  ObjectPropertySymbolicStateManager(v8::internal::Isolate* isolate);
  ~ObjectPropertySymbolicStateManager();

  // May return null shared pointer if there are no properties registered for
  // the given object
  std::shared_ptr<SymbolicState> GetSymbolicProperties(
      v8::internal::Handle<v8::internal::JSReceiver> target);

  void OnAssign(
      v8::internal::Handle<v8::internal::JSReceiver> target_literal,
      const SymbolicMemKeyValue& keyvalue);

  void Initialize();

private:

  class SymbolicObjectPropertyWrapper {
  public:
    inline SymbolicObjectPropertyWrapper(
        std::shared_ptr<SymbolicState> props)
      : wrapped_properties_(props) {}

    inline ~SymbolicObjectPropertyWrapper() {}

    inline std::shared_ptr<SymbolicState> GetProperties() const {
      return wrapped_properties_;
    }

    inline void SetProperties(
        std::shared_ptr<SymbolicState> props) {
      wrapped_properties_ = props;
    }

  private:
    std::shared_ptr<SymbolicState> wrapped_properties_;
  };


  std::shared_ptr<SymbolicState> NewProperties(
      v8::internal::Handle<v8::internal::JSReceiver> target_literal,
      const SymbolicKeyValue& keyval,
      std::shared_ptr<SymbolicState> maybe_previous);

  v8::internal::Handle<v8::internal::WeakHashTable> GetTable();

  v8::internal::Handle<v8::internal::Foreign> Wrap(
      std::shared_ptr<SymbolicState> props);

  SymbolicObjectPropertyWrapper* Lookup(
      v8::internal::Handle<v8::internal::JSReceiver> target_literal);

  GarbageCollectableManager<SymbolicObjectPropertyWrapper> garbage_;
  std::unique_ptr<LiteralValueHolder> weak_object_map_;
  v8::internal::Isolate* isolate_;
};


class ExpressionSlot : public std::enable_shared_from_this<ExpressionSlot> {
public:

  enum ControlFlowState {
    JUMP,
    BRANCH,
    SWITCH_TAG,
    ITERATOR_STATE,
    NONE,
    THROWABLE,
  };

  ExpressionSlot(ConcolicExecutor* context,
                 NodeLabel label,
                 std::vector<std::shared_ptr<ExpressionSlot>>&& deps,
                 SymbolicExecutor* sym);

  ExpressionSlot(ConcolicExecutor* context,
                 NodeLabel label,
                 SymbolicExecutor* sym);

  void HandleExecution(const ExecutionInfo& info);
  void HandleVariableLoadExecution(const VariableLoadExecutionInfo& info);
  SymbolicMemorySlot HandleAssignment(const ExecutionInfo& info);

  std::shared_ptr<SymbolicState> GetSymbolicState();
  void PopSymbolicState();
  std::shared_ptr<ExpressionSlot> GetDep(size_t i) const;
  size_t NumDeps() const;
  void SetControlFlowState(ControlFlowState val);
  void SetHasParent();
  void SetIsLeftOfBinaryPlus();
  void SetIsRightOfBinaryPlus();

  const NodeLabel& GetLabel() { return label_; }
  ConcolicExecutor* context() { return context_; }

private:
  enum NeedsToPrepareStackFrame {
    NO_PREPARATION,
    LEFT_OF_BINARY_PLUS,
    RIGHT_OF_BINARY_PLUS,
  };


  bool RecomputeHasSymbolicState();
  SymbolicMemorySlot CheckForTaint(
      const SymbolicFactory& fact,
      v8::internal::Handle<v8::internal::Object> eval);
  void PopChildren();
  SymbolicMemorySlot MakeExec(
      const SymbolicFactory& fact, const ExecutionInfo&);
  SymbolicMemorySlot MakeExec(
      const SymbolicFactory& fact, const VariableLoadExecutionInfo&);
  void PushExecution(SymbolicMemorySlot, const ExecutionInfo&);

  NodeLabel label_;
  ControlFlowState result_type_;
  std::vector<std::shared_ptr<ExpressionSlot>> depends_on_;
  ConcolicExecutor* context_;
  std::unique_ptr<SymbolicExecutor> sym_;
  bool feeds_other_;
  NeedsToPrepareStackFrame preparation_state_ = NO_PREPARATION;
};


class SymbolicStatement {
public:
  enum Type {
    TRY_CATCH,
    TRY_FINALLY,
    OTHER
  };

  SymbolicStatement();
  template <typename T> void Init(T, ConcolicExecutor* exec);

  Type GetType();

protected:
  Type type_;

private:

  static std::vector<std::shared_ptr<ExpressionSlot>> GetFrom(
      std::vector<::Ast::Expression::Reader> reader,
      ConcolicExecutor*);

  std::vector<std::shared_ptr<ExpressionSlot>> depends_;
};

enum IsCatchable {
  CATCHABLE,
  CATCHABLE_BY_FINALLY,
  NOT_CATCHABLE,
  CATCHABLE_BY_TOP_LEVEL
};


class SymbolicScope {
public:

  SymbolicScope(IsCatchable type);
  ~SymbolicScope();

  const SymbolicMemorySlot& FindIntermediate(
      std::shared_ptr<ExpressionSlot>);
  void RemoveIntermediate(std::shared_ptr<ExpressionSlot>);
  void InsertIntermediate(std::shared_ptr<ExpressionSlot>,
                          const SymbolicMemorySlot&);

  std::unique_ptr<SymbolicStackFrame> PopFrame();
  SymbolicStackFrame& PeekFrame();
  void NewFrame(FrameType frame_type, ConcolicExecutor* owner);

  IsCatchable GetCatchable();

  void PushAssignmentKey(const SymbolicMemKeyValue& keyobj);
  SymbolicMemKeyValue PopAssignmentKey();

private:
  std::vector<std::unique_ptr<SymbolicStackFrame>> preparing_frames_;

  // Key is the key used in assignment, value is the object
  std::vector<SymbolicMemKeyValue> assignment_key_stack_;

  std::map<std::shared_ptr<ExpressionSlot>,
           SymbolicMemorySlot> intermediate_values_;
  IsCatchable type_;
};


// Represents execution of an instance of a function. Stores symbolic values for
// intermediate values of expressions, function parameters, and function return
// values. Manages scopes for try-catch and try-finally blocks.
class SymbolicStackFrame {
public:

  SymbolicStackFrame(FrameType type, ConcolicExecutor* owner);
  ~SymbolicStackFrame();

  // Return the symbolic value of an argument in this frame. 0 is the first
  // argument provided to this function context.
  SymbolicMemorySlot GetArgument(uint32_t i) const;

  // Return the result of a previously executed expression in this stack frame.
  const SymbolicMemorySlot& GetExpression(
      std::shared_ptr<ExpressionSlot> target) const;

  // Returns the number of total arguments provided to the function call for
  // this stack frame.
  uint32_t NumArgs() const;

  // Add the symbolic value of an argument to a stack which is being prepared
  // for entering.
  void AddArgumentToPreparingFrame(const SymbolicMemorySlot& slot);

  // Add a literal argument to a stack which is being prepared for entering.
  // This may be ignored if the preparing frame already has symbolic values for
  // its parameters.
  void AddLiteralArgumentToPreparingFrame(const SymbolicMemorySlot& slot);

  // Set the symbolic value of the "receiver" (the "this" object) for the
  // currently preparing stack frame.
  void SetReceiverOnPreparingFrame(const SymbolicMemorySlot& slot);

  // Add a literal receiver to a stack which is being prepared for entering.
  // This may be ignored if the preparing frame already has a symbolic receiver.
  void SetLiteralReceiverOnPreparingFrame(const SymbolicMemorySlot& slot);

  void SetReceiverOnCurrentFrame(const SymbolicMemorySlot& slot);

  // Get the symbolic value of the "receiver"
  SymbolicMemorySlot& GetReceiver();
  bool HasReceiver();

  // Prepares a new stack frame and pushes the new frame onto the preparing
  // frame stack for the current scope.
  void OnPrepareFrame(FrameType frame_type);

  // Assign a symbolic value to an parameter argument for this stack frame.
  void AssignArgument(uint32_t idx, const SymbolicMemorySlot& other);

  // Registers the execution of the expression target in this stack frame. If
  // needs_temporary is true, then it will store value into the intermediate
  // values of the scope which can be retrieved later via a call to
  // GetExpression.
  SymbolicMemorySlot
  Execute(std::shared_ptr<ExpressionSlot> target,
          const SymbolicMemorySlot& value,
          bool needs_intermediate);

  // Removes an intermediate value for target from this stack frame.
  void Pop(std::shared_ptr<ExpressionSlot> target);

  enum FrameExitStatus {
    SHOULD_POP_MORE,
    SHOULD_STOP,
  };

  // Called on the frame currently exiting to signal that it should pass its
  // return value to the previous frame if necessary. This is only called for
  // cleanly exiting frames (e.g., called return or ended the function), not
  // when a frame exits as a result of a thrown exception.
  FrameExitStatus OnExit(SymbolicStackFrame& prev_frame);

  // Called when the frame is entered as the result of a function call. This
  // should return a pointer to an already prepared frame and remove that frame
  // from the preparing frame stack.
  std::unique_ptr<SymbolicStackFrame> OnEnter();

  // Set the return value for this instance of function call.
  void SetReturnValue(const SymbolicMemorySlot& slot);

  // Called on entry of a try-catch block. Pushes a new scope onto the scope
  // stack.
  void OnEnterTryCatch();

  // Called on entry of a try-finally block. Pushes a new scope onto the scope
  // stack.
  void OnEnterTryFinally();

  // Called when throw is called to pass the thrown exception up the stack.
  // HasThrownException must be true for the call to succeed.
  SymbolicMemorySlot TakeThrownException();
  bool HasThrownException();

  // Called to store the caught exception to the catch context.
  SymbolicMemorySlot TakeCaughtException();

  // Called when we exit a try block normally. Pops a scope from the scope
  // stack.
  void OnExitTry();

  // Called when an exception is thrown. Will signal that an exception should be
  // caught in which case it returns CATCHABLE or CATCHABLE_BY_FINALLY and pops
  // a scope from the scope stack, or returns NOT_CATCHABLE. If the exception is
  // caught by a catch block, then the frame must store the thrown_exception and
  // return it when TakeCaughtException is called.
  IsCatchable OnThrow(const SymbolicMemorySlot& thrown_exception);

  // Called to prepare a stack frame for a property setter accessor call.
  void PrepareForPropertySetterAccessorFrame(
      const SymbolicMemorySlot& receiver,
      const SymbolicMemorySlot& set_value);

  // Called to prepare a stack frame for a property getter accessor call.
  void PrepareForPropertyGetterAccessorFrame(
      const SymbolicMemorySlot& receiver);

  // Called to prepare a stack frame for throwing an exception.
  void PrepareForThrow(const SymbolicMemorySlot& throw_exp);

  // Prepare the frame to perform assign to this key.
  void PrepareForPropertyAssignmentKey(const SymbolicMemorySlot& receiver,
                                       const SymbolicMemorySlot& key);

  void PrepareForCallRuntimeCall(
      // Receiver for the function that is about to be called
      const SymbolicMemorySlot& receiver,

      // Function that is about to be called
      const SymbolicMemorySlot& target_function,

      // The arguments that are for the target_function call
      std::vector<SymbolicMemorySlot> fn_args);

  void PrepareForImplicitStringConversion(
      const SymbolicMemorySlot& receiver,

      // Should be either TO_STRING_CONVERT_PLUS_LEFT, or
      // TO_STRING_CONVERT_PLUS_RIGHT
      FrameType frame_type);

  // Take a previously prepared key
  SymbolicMemKeyValue TakeAssignmentPropertyKey();


  inline ConcolicExecutor* owner() { return owner_; }

  inline FrameType GetType() const { return type_; }

private:
  SymbolicScope& CurrentScope() const;

  SymbolicStackFrame();

  std::map<FrameType, std::vector<SymbolicMemorySlot>> potential_args_;

  // Holders for temporary values
  std::unique_ptr<SymbolicMemorySlot> return_value_;
  std::unique_ptr<SymbolicMemorySlot> merge_point_;
  std::unique_ptr<SymbolicMemorySlot> thrown_exception_;

  // Receiver object
  std::unique_ptr<SymbolicMemorySlot> receiver_;

  // Stack of caught exceptions
  std::vector<SymbolicMemorySlot> caught_exceptions_;

  // Function argument for this stack frame
  std::vector<SymbolicMemorySlot> args_;

  // Intermediate value scope
  std::vector<std::unique_ptr<SymbolicScope>> scope_stack_;
  ConcolicExecutor* owner_;
  FrameType type_;
};


class ConcolicExecutor {
public:

  ConcolicExecutor(v8::internal::Isolate*);
  ~ConcolicExecutor();

  void Initialize();

  void OnRuntimeHook(
      v8::internal::Handle<v8::internal::Object> branch_condition,
      v8::internal::Handle<v8::internal::Object> label,
      CheckType check);

  void OnRuntimeHookVariableLoad(
      v8::internal::Handle<v8::internal::Object> branch_condition,
      v8::internal::Handle<v8::internal::Object> proxy_label,
      v8::internal::Handle<v8::internal::Object> past_label,
      CheckType check);

  // The return value is only defined for EXPRESSION_VARIABLE_STORE
  v8::internal::Handle<v8::internal::Object> OnRuntimeHookVariableStore(
      v8::internal::Handle<v8::internal::Object> value,
      v8::internal::Handle<v8::internal::Object> label,
      CheckType check,

      // This is -1 for EXPRESSION_VARIABLE_STORE for
      // EXPRESSION_VARIABLE_STORE_CONTEXT, it is the index of the context where
      // the symbolic information is stored; for EXPRESSION_STORE_PARAMETER, it
      // is the index of the parameter variable. For EXPRESSION_PROPERTY_STORE,
      // it is the JSReceiver object that the property is being stored on.
      v8::internal::Handle<v8::internal::Object> var_idx);

  void OnRuntimeHookVariableContextStore(
    v8::internal::Handle<v8::internal::Object> concrete,
    v8::internal::Handle<v8::internal::Object> label,
    v8::internal::Handle<v8::internal::Context> context,
    v8::internal::Handle<v8::internal::Smi> smi);

  void OnRuntimeEnterTry(v8::internal::Handle<v8::internal::Object> label);
  void OnRuntimeExitTry(v8::internal::Handle<v8::internal::Object> label);
  void OnRuntimeThrow(
      v8::internal::Handle<v8::internal::Object> exception, bool is_rethrow);
  void OnRuntimeExitFinally();

  // Stores the symbolic values of the thrown_value in the context at the index
  // of Context::THROWN_OBJECT_INDEX + 1.
  void OnRuntimeCatch(v8::internal::Handle<v8::internal::Object> thrown_value,
                      v8::internal::Handle<v8::internal::Context> context);

  void OnRuntimeSetReturnValue(std::shared_ptr<SymbolicState> state);
  void OnRuntimeSetReturnValue(
      v8::internal::Handle<v8::internal::Object> value,
      v8::internal::MaybeHandle<v8::internal::Object> label);

  void OnRuntimeParameterToContextStorage(
      int parameter_index,
      int context_slot_index,
      v8::internal::Handle<v8::internal::Context> context);

  void RuntimePrepareApplyFrame(
    v8::internal::Handle<v8::internal::Object> argument_list,
    v8::internal::Handle<v8::internal::Object> target_fn,
    v8::internal::Handle<v8::internal::Object> new_target,
    v8::internal::Handle<v8::internal::Object> this_argument,
    FrameType caller_frame);

  void RuntimePrepareCallFrame(
    v8::internal::Handle<v8::internal::Object> target_fn,
    FrameType caller_frame_type,
    v8::internal::Handle<v8::internal::FixedArray> args);

  void RuntimePrepareCallOrConstructFrame(
    v8::internal::Handle<v8::internal::Object> target_fn,
    v8::internal::Handle<v8::internal::Object> new_target,
    v8::internal::Handle<v8::internal::FixedArray> args);

  void OnNewNode(const ::Ast::Expression::Reader& reader);
  void OnNewNode(const ::Ast::Statement::Reader& reader);


  SymbolicStackFrame& CurrentFrame();

  // May return null if there are no registered properties for this object.
  std::shared_ptr<SymbolicState> LookupObjectProperties(
      v8::internal::Handle<v8::internal::Object> object);

  uint32_t NumFrames();
  void ExitSymbolicStackFrame();
  void PrepareSymbolicStackFrame(FrameType frame_type);
  void EnterSymbolicStackFrame();

  void AddArgumentToFrame(
      v8::internal::MaybeHandle<v8::internal::Object> arg_label);
  void AddLiteralArgumentToFrame(
      v8::internal::Handle<v8::internal::Object> value);

  void SetReceiverOnFrame(
      v8::internal::Handle<v8::internal::Object> value,
      // Might be undefined, or a label serialized by a v8labelserializer
      v8::internal::Handle<v8::internal::Object> label);

  void SetLiteralReceiverOnCurrentFrame(
      v8::internal::Handle<v8::internal::Object> value);

  v8::internal::Handle<v8::internal::Object>
  GetSymbolicArgumentObject(uint32_t i);

  std::shared_ptr<SymbolicState> GetSymbolicArgumentState(uint32_t i);


  template <typename Reader>
  void MakeExpression(Reader reader, SymbolicExecutor*);
  void OnNewNode(const ::Ast::Declaration::Reader& reader);
  void OnNewNode(const ::Ast::FunctionLiteralNode::Reader& reader);
  void OnNewNode(const ::Ast::BlockNode::Reader& reader);
  void OnNewNode(const ::Ast::VariableProxyNode::Reader& reader);
  void OnNewNode(const ::Ast::CaseClause::Reader& reader);

  std::shared_ptr<ExpressionSlot> SlotFor(const NodeLabel& label);
  std::shared_ptr<ExpressionSlot> SlotFor(::Ast::NodeLabel::Reader label);
  bool HasLabel(const NodeLabel& label);

  void TookBranch(std::shared_ptr<SymbolicState>, bool);
  void TookJump(std::shared_ptr<SymbolicState>);
  void TookSwitch(std::shared_ptr<SymbolicState>);
  void TookIterator(std::shared_ptr<SymbolicState>);

  bool MatchesArgs(const v8::FunctionCallbackInfo<v8::Value>& info);

  v8::internal::Isolate* isolate() { return isolate_; }

private:
  std::shared_ptr<ExpressionSlot> NewSlot(const ::Ast::Expression::Reader& reader);
  void ThrowException(const SymbolicMemorySlot& symbolic_throwable);

  std::unordered_map<NodeLabel,
                     std::shared_ptr<ExpressionSlot>,
                     NodeLabel::Hash,
                     NodeLabel::EqualTo> nodes_;

  std::unordered_map<NodeLabel,
                     SymbolicStatement::Type,
                     NodeLabel::Hash,
                     NodeLabel::EqualTo> statements_;

  BuilderSerializer builder_serializer_;
  V8NodeLabelSerializer v8_serializer_;
  SymbolicMemorySlotSerializer mem_serializer_;
  ObjectPropertySymbolicStateManager object_manager_;
  std::vector<std::unique_ptr<SymbolicStackFrame>> executing_frames_;
  v8::internal::Isolate* isolate_;
};

bool SerializeAst(v8::internal::ParseInfo* info);

}

#endif
