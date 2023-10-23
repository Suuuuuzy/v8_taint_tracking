#include "src/ast/ast-expression-rewriter.h"
#include "src/parsing/parser.h"

#include "src/taint_tracking.h"
#include "src/taint_tracking-inl.h"
#include "src/string-stream.h"


#include "ast_serialization.h"

#include "ast.capnp.h"
#include "logrecord.capnp.h"

#include <tuple>


using namespace v8::internal;

namespace tainttracking {

const int INITIAL_OBJECT_PROPERTY_MAP_SIZE = 16;
const int SOURCE_HASH_PREFIX_MAX = 20;

std::string FrameTypeToString(FrameType frame_type) {
  switch (frame_type) {
    case FrameType::JS:
      return "JS";
    case FrameType::JS_CALL_NEW:
      return "JS_CALL_NEW";
    case FrameType::JS_CALL_RUNTIME:
      return "JS_CALL_RUNTIME";
    case FrameType::TOP_LEVEL:
      return "TOP_LEVEL";
    case FrameType::SETTER_ACCESSOR:
      return "SETTER_ACCESSOR";
    case FrameType::GETTER_ACCESSOR:
      return "GETTER_ACCESSOR";
    case FrameType::BUILTIN_CALL_OR_APPLY:
      return "BUILTIN_CALL_OR_APPLY";
    case FrameType::BUILTIN_REFLECT_APPLY:
      return "BUILTIN_REFLECT_APPLY";
    case FrameType::BUILTIN_REFLECT_CONSTRUCT:
      return "BUILTIN_REFLECT_CONSTRUCT";
    case FrameType::BUILTIN_APPLY:
      return "BUILTIN_APPLY";
    case FrameType::BUILTIN_CALL:
      return "BUILTIN_CALL";
    case FrameType::BUILTIN_CONSTRUCT:
      return "BUILTIN_CONSTRUCT";
    case FrameType::BUILTIN_CALL_FUNCTION:
      return "BUILTIN_CALL_FUNCTION";
    case FrameType::BUILTIN_CALL_BOUND_FUNCTION:
      return "BUILTIN_CALL_BOUND_FUNCTION";
    case FrameType::BUILTIN_CONSTRUCT_FUNCTION:
      return "BUILTIN_CONSTRUCT_FUNCTION";
    case FrameType::BUILTIN_FUNCTION_PROTOTYPE_CALL:
      return "BUILTIN_FUNCTION_PROTOTYPE_CALL";
    case FrameType::BUILTIN_FUNCTION_PROTOTYPE_APPLY:
      return "BUILTIN_FUNCTION_PROTOTYPE_APPLY";
    case FrameType::BUILTIN_JS_TRAMPOLINE:
      return "BUILTIN_JS_TRAMPOLINE";
    case FrameType::BUILTIN_INVOKE_FUNCTION_CODE:
      return "BUILTIN_INVOKE_FUNCTION_CODE";
    case FrameType::UNKNOWN_CAPI:
      return "UNKNOWN_CAPI";
    case FrameType::UNKNOWN_CAPI_NEW:
      return "UNKNOWN_CAPI_NEW";
    case FrameType::UNKNOWN_EXTERNAL:
      return "UNKNOWN_EXTERNAL";
    case FrameType::RUNTIME_CALL:
      return "RUNTIME_CALL";
    default:
      return "UnknownFrameType(" + std::to_string(frame_type) + ")";
  }
}



NodeLabel::NodeLabel(uint64_t rand, uint32_t counter) :
  rand_(rand), counter_(counter) {}

NodeLabel::NodeLabel() : rand_(0), counter_(0) {};

NodeLabel::NodeLabel(const NodeLabel& other) {
  CopyFrom(other);
}

bool NodeLabel::IsValid() const {
  return rand_ != 0 || counter_ != 0;
}

bool NodeLabel::Equals(const NodeLabel& other) const {
  return rand_ == other.rand_ && counter_ == other.counter_;
}

void NodeLabel::CopyFrom(const NodeLabel& other) {
  rand_ = other.rand_;
  counter_ = other.counter_;
}

NodeLabel::Labeler::Labeler(Isolate* isolate) :
  counter_(0),
  rng_(isolate->random_number_generator()) {}

NodeLabel NodeLabel::Labeler::New() {
  uint64_t next_value;
  rng_->NextBytes(&next_value, sizeof(next_value));
  return NodeLabel(next_value, counter_++);
}

NodeLabel::Rand NodeLabel::GetRand() const {
  return rand_;
}

NodeLabel::Counter NodeLabel::GetCounter() const {
  return counter_;
}


std::size_t NodeLabel::Hash::operator()(NodeLabel const& val) const {
  return underlying_(val.rand_);
}

bool NodeLabel::EqualTo::operator() (
    const NodeLabel& one, const NodeLabel& two) const {
  return one.Equals(two);
}


void HandleAstRawString(
    ::Ast::JsString::Builder str_builder, const AstRawString* str) {
  DCHECK_NOT_NULL(str);
  int byte_len = str->byte_length();
  auto segments = str_builder.initSegments(1);
  auto builder = segments[0];
  builder.setContent(::capnp::Data::Reader(str->raw_data(), byte_len));
  builder.setIsOneByte(str->is_one_byte());
}


Status ObjectOwnPropertiesVisitor::Visit(Handle<JSReceiver> receiver) {
  isolate_ = receiver->GetIsolate();
  value_stack_ = Handle<ArrayList>::cast(
      isolate_->factory()->NewFixedArray(0));
  if (!ProcessReceiver(receiver)) {
    return Status::FAILURE;
  }
  Object* undefined_value = isolate_->heap()->undefined_value();
  while (value_stack_->Length()) {
    int len_minus_one = value_stack_->Length() - 1;
    Handle<Object> curr = handle(value_stack_->Get(len_minus_one), isolate_);
    value_stack_->Set(len_minus_one, undefined_value);
    value_stack_->SetLength(len_minus_one);
    DCHECK(curr->IsJSReceiver());
    if (!ProcessReceiver(Handle<JSReceiver>::cast(curr))) {
      return Status::FAILURE;
    }
  }
  return Status::OK;
}

MaybeHandle<Object> FromLookupIterator(LookupIterator* it) {
  for (; it->IsFound(); it->Next()) {
    switch (it->state()) {
      case LookupIterator::NOT_FOUND:
      case LookupIterator::TRANSITION:
        UNREACHABLE();
        break;

      case LookupIterator::INTEGER_INDEXED_EXOTIC:
      case LookupIterator::JSPROXY:
      case LookupIterator::INTERCEPTOR:
      case LookupIterator::ACCESSOR:
        // TODO: should somehow make this available to caller. e.g. for
        // serialization, important to keep track of these, for copies maybe
        // not. These can run arbitrary javascript, so we should not call
        // them.
        break;

      case LookupIterator::ACCESS_CHECK:
        if (!it->HasAccess()) {
          return MaybeHandle<Object>();
        }
        break;

      case LookupIterator::DATA: {
        return it->GetDataValue();
      }
        break;
    }
  }
  return MaybeHandle<Object>();
}

Status ObjectOwnPropertiesVisitor::ProcessReceiver(
    Handle<JSReceiver> receiver) {
  // TODO: check if this might call an interceptor or a proxy object and if so,
  // stop doing that.
  MaybeHandle<FixedArray> maybe_entries =
    JSReceiver::OwnPropertyKeys(receiver);
  Handle<FixedArray> entries;
  if (!maybe_entries.ToHandle(&entries)) {
    return Status::FAILURE;
  }

  for (int i = 0; i < entries->length(); i++) {
    if (!entries->get(i)->IsString()) {
      // TODO: JavaScript Symbols (e.g., Symbol.species) are a reason why this
      // might fail. It would be good to check if this is the case, and then be
      // able to handle that case.
      continue;
    }
    Handle<String> key (String::cast(entries->get(i)), isolate_);

    LookupIterator it =
      LookupIterator::PropertyOrElement(isolate_, receiver, key);
    MaybeHandle<Object> maybe_property = FromLookupIterator(&it);
    Handle<Object> property;
    if (maybe_property.ToHandle(&property)) {
      if (VisitKeyValue(key, property) && property->IsJSReceiver()) {
        value_stack_ = ArrayList::Add(value_stack_, property);
      }
    } else {
      VisitKeyValue(
          key, handle(isolate_->heap()->undefined_value(), isolate_));
    }
  }
  return Status::OK;
}




void ObjectPropertySymbolicStateManager::OnAssign(
    v8::internal::Handle<v8::internal::JSReceiver> target_literal,
    const SymbolicMemKeyValue& keyvalue) {
  SymbolicObjectPropertyWrapper* prev = Lookup(target_literal);
  const SymbolicMemorySlot& key = keyvalue.GetKey();
  const SymbolicMemorySlot& value = keyvalue.GetValue();
  if (!key.HasSymbolicState() &&
      prev == nullptr &&
      !value.HasSymbolicState()) {
    return;
  }

  SymbolicKeyValue key_value_state (key.GetState(), value.GetState());
  if (prev) {
    prev->SetProperties(
        NewProperties(
            target_literal,
            key_value_state,
            prev->GetProperties()));
  } else {
    Handle<WeakHashTable> old_table = GetTable();
    Handle<WeakHashTable> new_table = WeakHashTable::Put(
        old_table,
        target_literal,
        Wrap(NewProperties(target_literal, key_value_state, nullptr)));
    if (*new_table != *old_table) {
      weak_object_map_.reset(new LiteralValueHolder(new_table, isolate_));
    }
  }
}



ObjectPropertySymbolicStateManager::ObjectPropertySymbolicStateManager(
    v8::internal::Isolate* isolate) :
  garbage_(isolate),
  weak_object_map_(),
  isolate_(isolate) {}

ObjectPropertySymbolicStateManager::~ObjectPropertySymbolicStateManager() {}

void ObjectPropertySymbolicStateManager::Initialize() {
  weak_object_map_.reset(
      new LiteralValueHolder(
          WeakHashTable::New(isolate_, INITIAL_OBJECT_PROPERTY_MAP_SIZE),
          isolate_));
}

std::shared_ptr<SymbolicState>
ObjectPropertySymbolicStateManager::GetSymbolicProperties(
    v8::internal::Handle<v8::internal::JSReceiver> target) {
  SymbolicObjectPropertyWrapper* prev = Lookup(target);
  return prev
    ? prev->GetProperties()
    : std::shared_ptr<SymbolicState>();
}


ObjectPropertySymbolicStateManager::SymbolicObjectPropertyWrapper*
ObjectPropertySymbolicStateManager::Lookup(
    v8::internal::Handle<v8::internal::JSReceiver> target_literal) {
  SymbolicObjectPropertyWrapper* prev_props = nullptr;
  Handle<Object> prev_handle =
    handle(GetTable()->Lookup(target_literal), isolate_);

  if (prev_handle->IsForeign()) {
    prev_props =
      reinterpret_cast<SymbolicObjectPropertyWrapper*>(
          Handle<Foreign>::cast(prev_handle)->foreign_address());
  } else {
    DCHECK(prev_handle->StrictEquals(isolate_->heap()->the_hole_value()));
  }
  return prev_props;
}

v8::internal::Handle<v8::internal::WeakHashTable>
ObjectPropertySymbolicStateManager::GetTable() {
  return Handle<WeakHashTable>::cast(weak_object_map_->Get());
}

v8::internal::Handle<v8::internal::Foreign>
ObjectPropertySymbolicStateManager::Wrap(
    std::shared_ptr<SymbolicState> props) {
  SymbolicObjectPropertyWrapper* new_wrapper =
    new SymbolicObjectPropertyWrapper(props);
  Handle<Foreign> wrapper_handle = isolate_->factory()->NewForeign(
      reinterpret_cast<Address>(new_wrapper));
  garbage_.New(
      wrapper_handle,
      std::unique_ptr<SymbolicObjectPropertyWrapper>(new_wrapper));
  return wrapper_handle;
}

std::shared_ptr<SymbolicState>
ObjectPropertySymbolicStateManager::NewProperties(
    v8::internal::Handle<v8::internal::JSReceiver> target_literal,
    const SymbolicKeyValue& key_value,
    std::shared_ptr<SymbolicState> maybe_previous) {
  if (!maybe_previous) {
    SymbolicFactory factory (target_literal->GetIsolate(), target_literal);
    maybe_previous = factory.FromLiteral();
    maybe_previous->ForceSerialization();
  }
  SymbolicFactory factory (target_literal->GetIsolate(), target_literal);
  return factory.ObjectWithSymbolicProperties(maybe_previous, key_value);
}




SymbolicMemorySlotSerializer::SymbolicMemorySlotSerializer(
    v8::internal::Isolate* isolate) :
  garbage_(isolate),
  isolate_(isolate) {}

SymbolicMemorySlotSerializer::~SymbolicMemorySlotSerializer() {}

v8::internal::Handle<v8::internal::Object>
SymbolicMemorySlotSerializer::Serialize(
    const SymbolicMemorySlot& slot) {
  SymbolicMemorySlot* copy = new SymbolicMemorySlot(slot);
  Handle<Object> new_answer = isolate_->factory()->NewForeign(
      reinterpret_cast<Address>(copy));
  garbage_.New(new_answer, std::unique_ptr<SymbolicMemorySlot>(copy));
  return new_answer;
}

SymbolicMemorySlot* SymbolicMemorySlotSerializer::Deserialize(
    v8::internal::Handle<v8::internal::Object> value) {
  if (!(value->IsForeign())) {
    bool equals_undefined =
      value->StrictEquals(isolate_->heap()->undefined_value());
    if (!equals_undefined) {
      value->Print(std::cerr);
    }
    DCHECK(equals_undefined);
    return nullptr;
  }

  return reinterpret_cast<SymbolicMemorySlot*>(
      Handle<Foreign>::cast(value)->foreign_address());
}

ExecutionInfo::ExecutionInfo(
    v8::internal::Handle<v8::internal::Object> eval,
    CheckType type) :
  eval_(eval), checktype_(type) {}

ExecutionInfo::~ExecutionInfo() {}

Handle<Object> ExecutionInfo::GetEval() const {
  return eval_;
}

CheckType ExecutionInfo::GetCheckType() const {
  return checktype_;
}

VariableLoadExecutionInfo::VariableLoadExecutionInfo(
      v8::internal::Handle<v8::internal::Object> eval,
      CheckType type,
      SymbolicMemorySlot* memslot) :
  ExecutionInfo(eval, type),
  slot_(memslot) {}

VariableLoadExecutionInfo::~VariableLoadExecutionInfo() {}

SymbolicMemorySlot* VariableLoadExecutionInfo::GetSlot() const {
  return slot_;
}

Status BuilderSerializer::Serialize(
    ::Ast::NodeLabel::Builder builder, const NodeLabel& label) {
  if (!label.IsValid()) {
    return Status::FAILURE;
  }
  builder.setNodeCompileConst(label.GetRand());
  builder.setNodeReference(label.GetCounter());
  return Status::OK;
}

Status BuilderSerializer::Deserialize(
    ::Ast::NodeLabel::Reader node, NodeLabel* label) {
  label->CopyFrom(
      NodeLabel(node.getNodeCompileConst(), node.getNodeReference()));
  return label->IsValid() ? Status::OK : Status::FAILURE;
}


SymbolicMemorySlot::SymbolicMemorySlot(
    bool has, std::shared_ptr<SymbolicState> state) :
  has_symbolic_state_(has),
  state_(state) {}

SymbolicMemorySlot::SymbolicMemorySlot(const SymbolicMemorySlot& other) :
  has_symbolic_state_(other.has_symbolic_state_),
  state_(other.state_) {}

bool SymbolicMemorySlot::HasSymbolicState() const {
  return has_symbolic_state_;
}

SymbolicMemorySlot& SymbolicMemorySlot::operator=(
    const SymbolicMemorySlot& other) {
  has_symbolic_state_ = other.has_symbolic_state_;
  state_ = other.state_;
  return *this;
}


std::shared_ptr<SymbolicState> SymbolicMemorySlot::GetState() const {
  return state_;
}


SymbolicScope::SymbolicScope(IsCatchable catchable_type) :
  preparing_frames_(),
  intermediate_values_(),
  type_(catchable_type) {}

SymbolicScope::~SymbolicScope() {}

IsCatchable SymbolicScope::GetCatchable() {
  return type_;
}

void SymbolicScope::InsertIntermediate(
    std::shared_ptr<ExpressionSlot> target,
    const SymbolicMemorySlot& slot) {
  intermediate_values_.insert(
      std::pair<std::shared_ptr<ExpressionSlot>, SymbolicMemorySlot>(
          target, slot));
}

const SymbolicMemorySlot& SymbolicScope::FindIntermediate(
    std::shared_ptr<ExpressionSlot> target) {
  auto iterator = intermediate_values_.find(target);

  #ifdef DEBUG
  if (iterator == intermediate_values_.end()) {
    std::cerr << "Node: " << target->GetLabel().GetRand() << " "
              << target->GetLabel().GetCounter() << std::endl;
    FATAL("Uninitialized symbolic state");
  }
  #endif

  return iterator->second;
}


void SymbolicScope::RemoveIntermediate(
    std::shared_ptr<ExpressionSlot> target) {
  auto iterator = intermediate_values_.find(target);

  #ifdef DEBUG
  if (iterator == intermediate_values_.end()) {
    std::cerr << "Node: " << target->GetLabel().GetRand() << " "
              << target->GetLabel().GetCounter() << std::endl;
    FATAL("Uninitialized symbolic state");
  }
  #endif

  intermediate_values_.erase(iterator);
}

std::unique_ptr<SymbolicStackFrame> SymbolicScope::PopFrame() {
  std::unique_ptr<SymbolicStackFrame> ret =
    std::move(preparing_frames_.back());
  preparing_frames_.pop_back();
  return ret;
}

SymbolicStackFrame& SymbolicScope::PeekFrame() {
  DCHECK_LT(0, preparing_frames_.size());
  DCHECK(preparing_frames_.back());
  return *(preparing_frames_.back());
}

void SymbolicScope::NewFrame(
    FrameType frame_type, ConcolicExecutor* owner) {
  preparing_frames_.push_back(
      std::unique_ptr<SymbolicStackFrame>(
          new SymbolicStackFrame(frame_type, owner)));
}


void SymbolicScope::PushAssignmentKey(const SymbolicMemKeyValue& key) {
  assignment_key_stack_.push_back(key);
}

SymbolicMemKeyValue SymbolicScope::PopAssignmentKey() {
  DCHECK_LT(0, assignment_key_stack_.size());
  SymbolicMemKeyValue ret_val = assignment_key_stack_.back();
  assignment_key_stack_.pop_back();
  return ret_val;
}



SymbolicStackFrame::SymbolicStackFrame(FrameType type, ConcolicExecutor* owner) :
  potential_args_(),
  return_value_(nullptr),
  merge_point_(),
  args_(),
  scope_stack_(),
  owner_(owner),
  type_(type) {
  // JavaScript calls will return undefined whether or not they
  // have an explicit return expression
  if (type_ == FrameType::JS) {
    SymbolicFactory fact(owner_->isolate());
    std::unique_ptr<SymbolicMemorySlot> ret(
        new SymbolicMemorySlot(false, fact.Undefined()));
    return_value_.swap(ret);
  }
  scope_stack_.push_back(
      std::unique_ptr<SymbolicScope>(
          new SymbolicScope(IsCatchable::NOT_CATCHABLE)));
}

SymbolicStackFrame::~SymbolicStackFrame() {
  // This checks for memory leaks
  // DCHECK_EQ(0, intermediate_values_.size());
}

SymbolicMemorySlot SymbolicStackFrame::GetArgument(uint32_t i) const {
  if (i >= args_.size()) {
    // Referencing unpassed arguments in javascript returns undefined
    SymbolicFactory fact (owner_->isolate());
    return SymbolicMemorySlot (false, fact.Undefined());
  } else {
    return args_[i];
  }
}

const SymbolicMemorySlot& SymbolicStackFrame::GetExpression(
    std::shared_ptr<ExpressionSlot> target) const {
  return CurrentScope().FindIntermediate(target);
}

void SymbolicStackFrame::AssignArgument(
    uint32_t idx, const SymbolicMemorySlot& other) {
  SymbolicFactory fact (owner_->isolate());
  while (idx >= args_.size()) {
    args_.push_back(SymbolicMemorySlot(false, fact.Undefined()));
  }
  DCHECK_LE(0, idx);
  DCHECK_LT(idx, args_.size());
  args_[idx] = other;
}


void SymbolicStackFrame::SetReceiverOnCurrentFrame(
    const SymbolicMemorySlot& slot) {
  receiver_.reset(new SymbolicMemorySlot(slot));
}

void SymbolicStackFrame::SetLiteralReceiverOnPreparingFrame(
    const SymbolicMemorySlot& slot) {
  SymbolicStackFrame& preparing_frame = CurrentScope().PeekFrame();
  std::unique_ptr<SymbolicMemorySlot>& receiver = preparing_frame.receiver_;
  if (!receiver) {
    receiver.reset(new SymbolicMemorySlot(slot));
  }
}

void SymbolicStackFrame::SetReceiverOnPreparingFrame(
    const SymbolicMemorySlot& slot) {
  SymbolicStackFrame& preparing_frame = CurrentScope().PeekFrame();
  auto& receiver = preparing_frame.receiver_;
  DCHECK(!receiver);
  receiver.reset(new SymbolicMemorySlot(slot));
  if (preparing_frame.type_ == FrameType::JS_CALL_RUNTIME) {
    // See note in AddArgumentToPreparingFrame for why we force serialization
    // here.
    slot.GetState()->ForceSerialization();
  }
}

SymbolicMemorySlot& SymbolicStackFrame::GetReceiver() {
  return *receiver_;
}

bool SymbolicStackFrame::HasReceiver() {
  return receiver_ ? true : false;
}


void SymbolicStackFrame::AddArgumentToPreparingFrame(
    const SymbolicMemorySlot& slot) {
  DCHECK(slot.GetState());
  SymbolicStackFrame& preparing_frame = CurrentScope().PeekFrame();
  if (preparing_frame.type_ == FrameType::JS_CALL_RUNTIME) {
    // We force serialization here because a runtime call can do arbitrary
    // things that we won't know about.
    slot.GetState()->ForceSerialization();
  }
  preparing_frame.args_.push_back(slot);
}

void SymbolicStackFrame::AddLiteralArgumentToPreparingFrame(
    const SymbolicMemorySlot& slot) {
  SymbolicStackFrame& prep = CurrentScope().PeekFrame();
  if (prep.type_ >= tainttracking::FrameType::FIRST_NEEDS_LITERAL) {
    prep.args_.push_back(slot);
  }
}

void SymbolicStackFrame::OnPrepareFrame(FrameType frame_type) {
  CurrentScope().NewFrame(frame_type, owner_);
}

SymbolicScope& SymbolicStackFrame::CurrentScope() const {
  DCHECK(scope_stack_.size() > 0);
  return *(scope_stack_.back());
}

SymbolicMemorySlot SymbolicStackFrame::Execute(
    std::shared_ptr<ExpressionSlot> target,
    const SymbolicMemorySlot& value,
    bool needs_temporary) {

  SymbolicMemorySlot to_store = value;
  if (merge_point_) {
    to_store =
      value.HasSymbolicState()
      ? SymbolicMemorySlot(
          true,
          SymbolicState::MergeWith(value.GetState(),
                                   merge_point_->GetState(),
                                   SymbolicState::MergeType::CALL,
                                   owner_->isolate()))
      : *merge_point_;
    merge_point_.reset();
  }

  if (needs_temporary) {
    CurrentScope().InsertIntermediate(target, to_store);
  }
  potential_args_.erase(potential_args_.begin(), potential_args_.end());
  return to_store;
}


uint32_t SymbolicStackFrame::NumArgs() const {
  return args_.size();
}

void SymbolicStackFrame::Pop(std::shared_ptr<ExpressionSlot> target) {
  CurrentScope().RemoveIntermediate(target);
}

void SymbolicStackFrame::PrepareForPropertySetterAccessorFrame(
    const SymbolicMemorySlot& receiver, const SymbolicMemorySlot& value) {
  potential_args_[FrameType::SETTER_ACCESSOR] = {{ receiver, value }};
}

void SymbolicStackFrame::PrepareForPropertyGetterAccessorFrame(
    const SymbolicMemorySlot& receiver) {
  potential_args_[FrameType::GETTER_ACCESSOR] = {{ receiver }};
}


std::unique_ptr<SymbolicStackFrame> SymbolicStackFrame::OnEnter() {
  std::unique_ptr<SymbolicStackFrame> next_frame =
    scope_stack_.back()->PopFrame();
  auto maybe_add_args = potential_args_.find(next_frame->type_);
  if (maybe_add_args != potential_args_.end()) {
    const std::vector<SymbolicMemorySlot>& frame_args = maybe_add_args->second;
    auto arg_iter = frame_args.begin();
    auto end_iter = frame_args.end();

    // First item is the receiver
    DCHECK(arg_iter != end_iter);
    next_frame->receiver_.reset(new SymbolicMemorySlot(*arg_iter));
    arg_iter++;

    for (; arg_iter != end_iter; arg_iter++) {
      next_frame->args_.push_back(*arg_iter);
    }
  }
  if (!next_frame->receiver_) {
    if (next_frame->type_ != FrameType::JS) {
      next_frame->receiver_.reset(
          new SymbolicMemorySlot(
              false,
              SymbolicFactory (owner_->isolate())
              .Uninstrumented(SymbolicFactory::RECEIVER)));
    } else {
      std::cerr << FrameTypeToString(next_frame->type_) << std::endl;
      // This should never happen for JS frame type
      UNREACHABLE();
    }
  }
  return next_frame;
}


SymbolicStackFrame::FrameExitStatus
SymbolicStackFrame::OnExit(SymbolicStackFrame& prev_frame) {
  // Special case for BUILTIN_APPLY frame type:
  //
  // This is required because the BUILTIN_APPLY does not have any other
  // opportunity to grab the return value of the internal BUILTIN_CALL frame
  // that it calls. What would happen without this, is that calls to apply would
  // not have the return value propogated up the stack.
  if (type_ == FrameType::BUILTIN_APPLY && merge_point_ && !return_value_) {
    return_value_.swap(merge_point_);
  }

  // Special case for RUNTIME_CALL frame type
  //
  // This is required because RUNTIME_CALL type from runtime-function.cc does
  // not have a pre-instrumented way to signify that the return value is the
  // return_value_ of the previous stack frame.
  if (type_ == FrameType::RUNTIME_CALL && merge_point_ && !return_value_) {
    return_value_.swap(merge_point_);
  }

  if (return_value_) {
    switch (type_) {
      case FrameType::BUILTIN_CALL_OR_APPLY:
      case FrameType::BUILTIN_REFLECT_APPLY:
      case FrameType::BUILTIN_REFLECT_CONSTRUCT:
      case FrameType::BUILTIN_APPLY:
      case FrameType::BUILTIN_CALL:
      case FrameType::BUILTIN_CONSTRUCT:
      case FrameType::BUILTIN_CALL_FUNCTION:
      case FrameType::BUILTIN_CALL_BOUND_FUNCTION:
      case FrameType::BUILTIN_CONSTRUCT_FUNCTION:
      case FrameType::BUILTIN_FUNCTION_PROTOTYPE_CALL:
      case FrameType::BUILTIN_FUNCTION_PROTOTYPE_APPLY:
      case FrameType::BUILTIN_JS_TRAMPOLINE:
      case FrameType::BUILTIN_INVOKE_FUNCTION_CODE:
      case FrameType::RUNTIME_CALL:
      case FrameType::JS:
      case FrameType::GETTER_ACCESSOR:
      case FrameType::JS_CALL_RUNTIME:
      case FrameType::TO_STRING_CONVERT_PLUS_LEFT:
      case FrameType::TO_STRING_CONVERT_PLUS_RIGHT:

        // moving this outside of the switch makes it work but will cause other
        // things to error
        prev_frame.merge_point_.swap(return_value_);
        break;
      case FrameType::JS_CALL_NEW:
        DCHECK(receiver_);
        prev_frame.merge_point_.swap(receiver_);
        break;

      default:
        break;
    }
  }

  if (type_ >= FrameType::FIRST_NEEDS_AUTO_EXIT &&
      type_ <= FrameType::LAST_NEEDS_AUTO_EXIT) {
    // This frame should also exit because in builtins-x64.cc we do not have
    // the opportunity to call the frame exit.
    return FrameExitStatus::SHOULD_POP_MORE;
  } else {
    return FrameExitStatus::SHOULD_STOP;
  }
}


SymbolicMemorySlot SymbolicStackFrame::TakeThrownException() {
  SymbolicMemorySlot thrown_copy = *thrown_exception_;
  thrown_exception_.reset();
  return thrown_copy;
}

bool SymbolicStackFrame::HasThrownException() {
  return thrown_exception_ ? true : false;
}

SymbolicMemorySlot SymbolicStackFrame::TakeCaughtException() {
#ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    std::cerr << "Popping caught exception. Size before pop: "
              << caught_exceptions_.size() << std::endl;
  }
#endif

  SymbolicMemorySlot caught = caught_exceptions_.back();
  caught_exceptions_.pop_back();
  return caught;
}


void SymbolicStackFrame::PrepareForThrow(
    const SymbolicMemorySlot& thrown_exp) {
  thrown_exception_.reset(new SymbolicMemorySlot(thrown_exp));
}


  // Prepare the frame to perform assign to this key.
void SymbolicStackFrame::PrepareForPropertyAssignmentKey(
    const SymbolicMemorySlot& receiver, const SymbolicMemorySlot& key) {
  CurrentScope().PushAssignmentKey(SymbolicMemKeyValue(key, receiver));
}

// Take a previously prepared key
SymbolicMemKeyValue SymbolicStackFrame::TakeAssignmentPropertyKey() {
  return CurrentScope().PopAssignmentKey();
}


void SymbolicStackFrame::PrepareForCallRuntimeCall(
    // Receiver for the function that is about to be called
    const SymbolicMemorySlot& receiver,

    // Function that is about to be called
    const SymbolicMemorySlot&,

    // The arguments that are for the target_function call
    std::vector<SymbolicMemorySlot> fn_args) {
  std::vector<SymbolicMemorySlot>& args = potential_args_[FrameType::RUNTIME_CALL];
  args.clear();
  args.push_back(receiver);
  for (auto& arg : fn_args) {
    args.push_back(arg);
  }
}

void SymbolicStackFrame::PrepareForImplicitStringConversion(
    const SymbolicMemorySlot& receiver,
    FrameType type) {
  DCHECK(type == TO_STRING_CONVERT_PLUS_LEFT ||
         type == TO_STRING_CONVERT_PLUS_RIGHT);
  potential_args_[type].push_back(receiver);
}



void SymbolicStackFrame::OnEnterTryCatch() {
  scope_stack_.push_back(
      std::unique_ptr<SymbolicScope>(
          new SymbolicScope(IsCatchable::CATCHABLE)));
}

void SymbolicStackFrame::OnEnterTryFinally() {
  scope_stack_.push_back(
      std::unique_ptr<SymbolicScope>(
          new SymbolicScope(IsCatchable::CATCHABLE_BY_FINALLY)));
}

void SymbolicStackFrame::OnExitTry() {
  // 2 because we want to always have at least one scope on the stack.
  DCHECK_LE(2, scope_stack_.size());
  scope_stack_.pop_back();
}

IsCatchable SymbolicStackFrame::OnThrow(const SymbolicMemorySlot& thrown) {
  // When scope_stack_.size() == 1, all we have is the first scope stack which
  // cannot catch anything.
  while (scope_stack_.size() > 1) {
    IsCatchable is_catchable_by_javascript = CurrentScope().GetCatchable();
    OnExitTry();
    switch (is_catchable_by_javascript) {
      case IsCatchable::CATCHABLE:
      case IsCatchable::CATCHABLE_BY_FINALLY:
        #ifdef DEBUG
        if (FLAG_taint_tracking_trace_concolic) {
          std::cerr << "Pushing caught exception. Size before push: "
                    << caught_exceptions_.size() << std::endl;
        }
        #endif

        caught_exceptions_.push_back(thrown);
        return is_catchable_by_javascript;

      case IsCatchable::NOT_CATCHABLE:
        break;

      default:
        UNREACHABLE();
        break;
    }
  }


  // TODO: Have a better design for detecting when stack frames are rolled back.
  switch (type_) {
    case FrameType::TOP_LEVEL:
    case FrameType::SETTER_ACCESSOR:
    case FrameType::GETTER_ACCESSOR:
    case FrameType::UNKNOWN_CAPI:
    case FrameType::UNKNOWN_CAPI_NEW:
    case FrameType::UNKNOWN_EXTERNAL:
      return IsCatchable::CATCHABLE_BY_TOP_LEVEL;

    case FrameType::JS:
    case FrameType::JS_CALL_NEW:
    default:
      return NOT_CATCHABLE;
  }
}


void SymbolicStackFrame::SetReturnValue(
    const SymbolicMemorySlot& slot) {
  return_value_ = std::unique_ptr<SymbolicMemorySlot>(
      new SymbolicMemorySlot(slot));
}

ConcolicExecutor::ConcolicExecutor(v8::internal::Isolate* isolate) :
  v8_serializer_(isolate),
  mem_serializer_(isolate),
  object_manager_(isolate),
  isolate_(isolate) {
  DCHECK_NOT_NULL(isolate);

  // This top level frame seems to be required for bootstrapping the native
  // context which does not have a function call.
  executing_frames_.push_back(
      std::unique_ptr<SymbolicStackFrame>(
          new SymbolicStackFrame(TOP_LEVEL, this)));
}

uint32_t ConcolicExecutor::NumFrames() {
  return executing_frames_.size();
}

ConcolicExecutor::~ConcolicExecutor() {}

SymbolicStackFrame& ConcolicExecutor::CurrentFrame() {
  DCHECK_LT(0, executing_frames_.size());
  return *(executing_frames_.back());
}

void ConcolicExecutor::OnRuntimeSetReturnValue(
    std::shared_ptr<SymbolicState> state) {
  CurrentFrame().SetReturnValue(SymbolicMemorySlot(true, state));
}

void ConcolicExecutor::OnRuntimeSetReturnValue(
    v8::internal::Handle<v8::internal::Object> value,
    v8::internal::MaybeHandle<v8::internal::Object> maybe_label) {
  SymbolicStackFrame& frame = CurrentFrame();
  Handle<Object> label;
  if (maybe_label.ToHandle(&label)) {
    NodeLabel slot_label;
    DCHECK(v8_serializer_.Deserialize(label, &slot_label));
    frame.SetReturnValue(frame.GetExpression(SlotFor(slot_label)));
  } else {
    SymbolicFactory factory (isolate_);
    frame.SetReturnValue(SymbolicMemorySlot(false, factory.Undefined()));
  }
}


void ConcolicExecutor::OnRuntimeEnterTry(
    v8::internal::Handle<v8::internal::Object> label) {
  NodeLabel statement_label;
  DCHECK(v8_serializer_.Deserialize(label, &statement_label));
  auto iterator = statements_.find(statement_label);
  DCHECK(iterator != statements_.end());
  if (iterator->second == SymbolicStatement::TRY_CATCH) {
    CurrentFrame().OnEnterTryCatch();
  } else {
    DCHECK_EQ(iterator->second, SymbolicStatement::TRY_FINALLY);
    CurrentFrame().OnEnterTryFinally();
  }
}

void ConcolicExecutor::OnRuntimeExitTry(
    v8::internal::Handle<v8::internal::Object> label) {
  CurrentFrame().OnExitTry();
}

void ConcolicExecutor::ThrowException(
    const SymbolicMemorySlot& symbolic_throwable) {
  IsCatchable state = CurrentFrame().OnThrow(symbolic_throwable);
  while (state == IsCatchable::NOT_CATCHABLE) {
    DCHECK_LT(0, executing_frames_.size());
    executing_frames_.pop_back();
    state = CurrentFrame().OnThrow(symbolic_throwable);
  }
}

void ConcolicExecutor::OnRuntimeThrow(
    v8::internal::Handle<v8::internal::Object> exception, bool) {

  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    std::cerr << "Exception" << std::endl;
    exception->ShortPrint(std::cerr);
    std::cerr << std::endl;
  }
  #endif

  if (CurrentFrame().HasThrownException()) {
    ThrowException(CurrentFrame().TakeThrownException());
  } else {
    SymbolicFactory fact (isolate_, exception, NodeLabel());
    ThrowException(
        SymbolicMemorySlot(
            false,
            fact.Uninstrumented(SymbolicFactory::THROWN_EXCEPTION)));
  }
}

std::shared_ptr<SymbolicState> ConcolicExecutor::LookupObjectProperties(
    v8::internal::Handle<v8::internal::Object> object) {
  if (object->IsJSReceiver()) {
    std::shared_ptr<SymbolicState> props =
      object_manager_.GetSymbolicProperties(Handle<JSReceiver>::cast(object));
    if (props) {
      return props;
    }
  }
  return std::shared_ptr<SymbolicState>();
}

void ConcolicExecutor::OnRuntimeCatch(
    v8::internal::Handle<v8::internal::Object> thrown_value,
    v8::internal::Handle<v8::internal::Context> context) {
  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    std::cerr << "Entering catch after throwing exception. Frame size: "
              << executing_frames_.size() << std::endl;
  }
  #endif

  DCHECK_GT(context->length(), Context::THROWN_OBJECT_INDEX + 1);
  context->set(
      Context::THROWN_OBJECT_INDEX + 1,
      *mem_serializer_.Serialize(CurrentFrame().TakeCaughtException()));
}

void ConcolicExecutor::OnRuntimeExitFinally() {
  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    std::cerr << "rethrowing finally current frame stack size "
              << executing_frames_.size() << std::endl;
  }
  #endif

  ThrowException(CurrentFrame().TakeCaughtException());
}


void ConcolicExecutor::ExitSymbolicStackFrame() {
  SymbolicStackFrame::FrameExitStatus status =
    SymbolicStackFrame::FrameExitStatus::SHOULD_POP_MORE;
  while (status == SymbolicStackFrame::FrameExitStatus::SHOULD_POP_MORE) {
    DCHECK_LT(1, executing_frames_.size());
    std::unique_ptr<SymbolicStackFrame> exiting =
      std::move(executing_frames_.back());
    executing_frames_.pop_back();
    status = exiting->OnExit(*executing_frames_.back());
  }

  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    std::cerr << "exiting frame. Stack size after exit: "
              << executing_frames_.size()
              << ". Current frame type: "
              << FrameTypeToString(CurrentFrame().GetType()) << std::endl;
  }
  #endif
}

void ConcolicExecutor::PrepareSymbolicStackFrame(
    FrameType frame_type) {
  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    std::cerr << "preparing frame type: " <<
      FrameTypeToString(frame_type) << std::endl;
  }
  #endif

  CurrentFrame().OnPrepareFrame(frame_type);
}

void ConcolicExecutor::EnterSymbolicStackFrame() {
  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    auto& current_frame = CurrentFrame();
    std::cerr << "Before entering frame. Stack size before enter: "
              << executing_frames_.size()
              << ". Current frame type "
              << FrameTypeToString(current_frame.GetType())
              << std::endl
              << "Receiver: ";
    if (current_frame.HasReceiver()) {
      current_frame.GetReceiver().GetState()->DebugPrintObject();
    } else {
      std::cerr << "[NO_RECEIVER]";
    }
    std::cerr << std::endl;
  }
  #endif

  executing_frames_.push_back(executing_frames_.back()->OnEnter());

  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    auto& current_frame = CurrentFrame();
    std::cerr << "After entering frame. Stack size after enter: "
              << executing_frames_.size()
              << ". Current frame type "
              << FrameTypeToString(current_frame.GetType())
              << std::endl
              << "Receiver: ";
    if (current_frame.HasReceiver()) {
      current_frame.GetReceiver().GetState()->DebugPrintObject();
    } else {
      std::cerr << "[NO_RECEIVER]";
    }
    std::cerr << std::endl;
  }
  #endif
}


void ConcolicExecutor::SetLiteralReceiverOnCurrentFrame(
    v8::internal::Handle<v8::internal::Object> value) {
  CurrentFrame().SetReceiverOnCurrentFrame(
      SymbolicMemorySlot(
          false,
          SymbolicFactory(isolate_, value).FromLiteral()));
}

void ConcolicExecutor::SetReceiverOnFrame(
    v8::internal::Handle<v8::internal::Object> value,
    // Might be undefined, or a label serialized by a v8labelserializer
    v8::internal::Handle<v8::internal::Object> label) {
  if (label->IsUndefined(isolate_)) {
    CurrentFrame().SetLiteralReceiverOnPreparingFrame(
        SymbolicMemorySlot(
            false,
            SymbolicFactory (isolate_, value).FromLiteral()));
  } else {
    NodeLabel deserialized_label;
    DCHECK(v8_serializer_.Deserialize(label, &deserialized_label));
    SymbolicMemorySlot symbolic_value =
      CurrentFrame().GetExpression(SlotFor(deserialized_label));
    DCHECK(symbolic_value.GetState()->DebugCheckObjectEquals(value));
    CurrentFrame().SetReceiverOnPreparingFrame(symbolic_value);
  }
}


void ConcolicExecutor::AddArgumentToFrame(
    v8::internal::MaybeHandle<v8::internal::Object> maybe_arg_label) {
  Handle<Object> arg_label;
  if (maybe_arg_label.ToHandle(&arg_label)) {
    NodeLabel label;
    DCHECK(v8_serializer_.Deserialize(arg_label, &label));
    CurrentFrame().AddArgumentToPreparingFrame(
        CurrentFrame().GetExpression(SlotFor(label)));
  } else {
    SymbolicFactory factory(isolate_);
    CurrentFrame().AddArgumentToPreparingFrame(
        SymbolicMemorySlot (
            false,
            factory.Uninstrumented(SymbolicFactory::ARGUMENT)));
  }
}

void ConcolicExecutor::AddLiteralArgumentToFrame(
    v8::internal::Handle<v8::internal::Object> value) {
  SymbolicFactory factory (isolate_, value, NodeLabel());
  CurrentFrame().AddLiteralArgumentToPreparingFrame(
      SymbolicMemorySlot(false, factory.FromLiteral()));
}

v8::internal::Handle<v8::internal::Object>
ConcolicExecutor::GetSymbolicArgumentObject(uint32_t i) {
  return mem_serializer_.Serialize(CurrentFrame().GetArgument(i));
}

std::shared_ptr<SymbolicState>
ConcolicExecutor::GetSymbolicArgumentState(uint32_t i) {
  return CurrentFrame().GetArgument(i).GetState();
}


std::string CheckTypeToString(tainttracking::CheckType checktype) {
  switch (checktype) {
    case CheckType::STATEMENT_BEFORE:
      return "STATEMENT_BEFORE";
    case CheckType::STATEMENT_AFTER:
      return "STATEMENT_AFTER";
    case CheckType::EXPRESSION_BEFORE:
      return "EXPRESSION_BEFORE";
    case CheckType::EXPRESSION_AFTER:
      return "EXPRESSION_AFTER";
    case CheckType::EXPRESSION_AFTER_OPTIMIZED_OUT:
      return "EXPRESSION_AFTER_OPTIMIZED_OUT";
    case CheckType::EXPRESSION_UNEXECUTED:
      return "EXPRESSION_UNEXECUTED";
    case CheckType::STATIC_VALUE_CHECK:
      return "STATIC_VALUE_CHECK";
    case CheckType::EXPRESSION_VARIABLE_LOAD_GLOBAL:
      return "EXPRESSION_VARIABLE_LOAD_GLOBAL";
    case CheckType::EXPRESSION_PARAMETER_LOAD:
      return "EXPRESSION_PARAMETER_LOAD";
    case CheckType::EXPRESSION_PARAMETER_STORE:
      return "EXPRESSION_PARAMETER_STORE";
    case CheckType::EXPRESSION_VARIABLE_LOAD:
      return "EXPRESSION_VARIABLE_LOAD";
    case CheckType::EXPRESSION_VARIABLE_LOAD_CONTEXT_LOOKUP:
      return "EXPRESSION_VARIABLE_LOAD_CONTEXT_LOOKUP";
    case CheckType::EXPRESSION_VARIABLE_STORE:
      return "EXPRESSION_VARIABLE_STORE";
    case CheckType::EXPRESSION_PROPERTY_STORE:
      return "EXPRESSION_PROPERTY_STORE";
    case CheckType::EXPRESSION_LVALUE:
      return "EXPRESSION_LVALUE";
    case CheckType::EXPRESSION_PROPERTY_LVALUE:
      return "EXPRESSION_PROPERTY_LVALUE";
    case CheckType::EXPRESSION_VARIABLE_STORE_CONTEXT:
      return "EXPRESSION_VARIABLE_STORE_CONTEXT";
    default:
      return "UNKNOWN";
  }
}

inline void DebugPrintTraceHook(
    const NodeLabel& label, const ExecutionInfo& info) {
  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    std::cerr << CheckTypeToString(info.GetCheckType()) << ": "
              << label.GetRand() << " " << label.GetCounter() << std::endl;
    info.GetEval()->ShortPrint(std::cerr);
    std::cerr << std::endl;
  }
  #endif
}


void ConcolicExecutor::OnRuntimeHook(
    v8::internal::Handle<v8::internal::Object> branch_condition,
    v8::internal::Handle<v8::internal::Object> label,
    CheckType check) {
  NodeLabel node_label;
  ExecutionInfo info(branch_condition, check);
  DCHECK(v8_serializer_.Deserialize(label, &node_label));
  DebugPrintTraceHook(node_label, info);
  SlotFor(node_label)->HandleExecution(info);
}

void ConcolicExecutor::OnRuntimeHookVariableLoad(
    Handle<Object> branch_condition,
    Handle<Object> proxy_label,
    Handle<Object> past_label_or_parameter_index,
    CheckType check) {

  NodeLabel label;
  DCHECK(v8_serializer_.Deserialize(proxy_label, &label));
  std::shared_ptr<ExpressionSlot> expr_slot = SlotFor(label);

  switch (check) {
    case EXPRESSION_PARAMETER_LOAD: {
      DCHECK(past_label_or_parameter_index->IsSmi());
      int param_idx = Smi::cast(*past_label_or_parameter_index)->value();
      DCHECK_LE(RECEIVER_VARIABLE_INDEX, param_idx);
      if (param_idx != RECEIVER_VARIABLE_INDEX) {
        DCHECK_LE(0, param_idx);
        SymbolicMemorySlot mem_slot (CurrentFrame().GetArgument(param_idx));
        VariableLoadExecutionInfo info(branch_condition, check, &mem_slot);
        DebugPrintTraceHook(label, info);
        expr_slot->HandleVariableLoadExecution(info);
      } else {
        DCHECK_EQ(RECEIVER_VARIABLE_INDEX, param_idx);
        SymbolicMemorySlot mem_slot (CurrentFrame().GetReceiver());
        VariableLoadExecutionInfo info(branch_condition, check, &mem_slot);
        DebugPrintTraceHook(label, info);
        expr_slot->HandleVariableLoadExecution(info);
      }
    }
      break;

    default: {
      VariableLoadExecutionInfo info(
          branch_condition,
          check,
          mem_serializer_.Deserialize(past_label_or_parameter_index));
      DebugPrintTraceHook(label, info);
      expr_slot->HandleVariableLoadExecution(info);
    }
      break;
  }
}


std::shared_ptr<ExpressionSlot>
ConcolicExecutor::SlotFor(const NodeLabel& label) {
  DCHECK(label.IsValid());
  auto contains = nodes_.find(label);
  DCHECK(contains != nodes_.end());
  return contains->second;
}

std::shared_ptr<ExpressionSlot>
ConcolicExecutor::SlotFor(::Ast::NodeLabel::Reader label) {
  NodeLabel node_label;
  if (!builder_serializer_.Deserialize(label, &node_label)) {
    std::cerr << label.getNodeReference() << " "
              << label.getNodeCompileConst() << std::endl;
    UNREACHABLE();
  }
  return SlotFor(node_label);
}

bool ConcolicExecutor::HasLabel(const NodeLabel& label) {
  return nodes_.find(label) == nodes_.end();
}

bool ConcolicExecutor::MatchesArgs(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  SymbolicStackFrame& frame = CurrentFrame();
  if (info.Length() != frame.NumArgs()) {
    std::cerr << "length " << info.Length() << " "
              << frame.NumArgs() << std::endl;
    return false;
  }
  bool matches = true;
  for (int i = 0; i < info.Length(); i++) {
    matches &= frame.GetArgument(i).GetState()->DebugCheckObjectEquals(
        v8::Utils::OpenHandle(*(info[i])));
    if (!matches) {
      std::cerr << "equals " << info.Length() << " " << i << "\n";
      v8::Utils::OpenHandle(*(info[i]))->ShortPrint(std::cerr);
      std::cerr << "\n";
      frame.GetArgument(i).GetState()->DebugPrintObject();
      std::cerr << "\n";
    }
  }
  return matches;
}

class DummyExpressionSlot : public SymbolicExecutor {};

void ConcolicExecutor::OnNewNode(const ::Ast::Expression::Reader& reader) {
  NodeLabel key;
  DCHECK(builder_serializer_.Deserialize(reader.getNode().getLabel(), &key));
  DCHECK(nodes_.find(key) == nodes_.end());
  nodes_[key] = std::shared_ptr<ExpressionSlot>(NewSlot(reader));
}


std::vector<std::shared_ptr<ExpressionSlot>> SymbolicStatement::GetFrom(
    std::vector<::Ast::Expression::Reader> readers,
    ConcolicExecutor* context) {
  std::vector<std::shared_ptr<ExpressionSlot>> expr;
  for (auto& reader : readers) {
    expr.push_back(context->SlotFor(reader.getNode().getLabel()));
  }
  return expr;
}

SymbolicStatement::Type SymbolicStatement::GetType() {
  return type_;
}

template <> void
SymbolicStatement::Init<::Ast::DoWhileStatement::Reader>(
    ::Ast::DoWhileStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = GetFrom({{ reader.getCond() }}, exec);
  depends_[0]->SetControlFlowState(
      ExpressionSlot::ControlFlowState::BRANCH);
}

template <> void
SymbolicStatement::Init<::Ast::WhileStatement::Reader>(
    ::Ast::WhileStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = GetFrom({{ reader.getCond() }}, exec);
  depends_[0]->SetControlFlowState(
      ExpressionSlot::ControlFlowState::BRANCH);
}

template <> void
SymbolicStatement::Init<::Ast::ForStatement::Reader>(
    ::Ast::ForStatement::Reader reader, ConcolicExecutor* exec) {
  std::vector<::Ast::Expression::Reader> answer;
  bool has_branch = false;
  if (reader.hasCond()) {
    answer.push_back(reader.getCond());
    has_branch = true;
  }
  depends_ = GetFrom(std::move(answer), exec);
  if (has_branch) {
    depends_[0]->SetControlFlowState(
        ExpressionSlot::ControlFlowState::BRANCH);
  }
}

template <> void
SymbolicStatement::Init<::Ast::ForInStatement::Reader>(
    ::Ast::ForInStatement::Reader reader, ConcolicExecutor* exec) {
  std::vector<::Ast::Expression::Reader> answer;
  answer.push_back(reader.getEach());
  answer.push_back(reader.getSubject());
  depends_ = GetFrom(std::move(answer), exec);
  depends_[1]->SetControlFlowState(
      ExpressionSlot::ControlFlowState::ITERATOR_STATE);
}

template <> void
SymbolicStatement::Init<::Ast::ForOfStatement::Reader>(
    ::Ast::ForOfStatement::Reader reader, ConcolicExecutor* exec) {
  std::vector<::Ast::Expression::Reader> answer;
  answer.push_back(reader.getAssignIterator());
  answer.push_back(reader.getNextResult());
  answer.push_back(reader.getResultDone());
  answer.push_back(reader.getAssignEach());
  depends_ = GetFrom(std::move(answer), exec);
}

template <> void
SymbolicStatement::Init<::Ast::Block::Reader>(
    ::Ast::Block::Reader reader, ConcolicExecutor* exec) {
  depends_ = std::vector<std::shared_ptr<ExpressionSlot>>();
}

template <> void
SymbolicStatement::Init<::Ast::EmptyStatement::Reader>(
    ::Ast::EmptyStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = std::vector<std::shared_ptr<ExpressionSlot>>();
}

template <> void
SymbolicStatement::Init<::Ast::SwitchStatement::Reader>(
    ::Ast::SwitchStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = GetFrom({{ reader.getTag() }}, exec);
  depends_[0]->SetControlFlowState(
      ExpressionSlot::ControlFlowState::SWITCH_TAG);
}

template <> void
SymbolicStatement::Init<::Ast::ContinueStatement::Reader>(
    ::Ast::ContinueStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = std::vector<std::shared_ptr<ExpressionSlot>>();
}

template <> void
SymbolicStatement::Init<::Ast::BreakStatement::Reader>(
    ::Ast::BreakStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = std::vector<std::shared_ptr<ExpressionSlot>>();
}

template <> void
SymbolicStatement::Init<::Ast::TryCatchStatement::Reader>(
    ::Ast::TryCatchStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = std::vector<std::shared_ptr<ExpressionSlot>>();
  type_ = Type::TRY_CATCH;
}

template <> void
SymbolicStatement::Init<::Ast::TryFinallyStatement::Reader>(
    ::Ast::TryFinallyStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = std::vector<std::shared_ptr<ExpressionSlot>>();
  type_ = Type::TRY_FINALLY;
}

template <> void
SymbolicStatement::Init<::Ast::IfStatement::Reader>(
    ::Ast::IfStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = GetFrom({{ reader.getCond() }}, exec);
  depends_[0]->SetControlFlowState(
      ExpressionSlot::ControlFlowState::BRANCH);
}

template <> void
SymbolicStatement::Init<::Ast::ReturnStatement::Reader>(
    ::Ast::ReturnStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = GetFrom({{ reader.getValue() }}, exec);
  depends_[0]->SetHasParent();
}

template <> void
SymbolicStatement::Init<::Ast::WithStatement::Reader>(
    ::Ast::WithStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = GetFrom({{ reader.getExpression() }}, exec);
}

template <> void
SymbolicStatement::Init<::Ast::ExpressionStatement::Reader>(
    ::Ast::ExpressionStatement::Reader reader, ConcolicExecutor* exec) {
  depends_ = GetFrom({{ reader.getExpression() }}, exec);
}


void ConcolicExecutor::OnNewNode(const ::Ast::Statement::Reader& reader) {
  auto node_val = reader.getNodeVal();
  NodeLabel label;
  DCHECK(builder_serializer_.Deserialize(
      reader.getNode().getLabel(), &label));
  SymbolicStatement state;
  switch (node_val.which()) {
    case ::Ast::Statement::NodeVal::IF_STATEMENT:
      state.Init(node_val.getIfStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::FOR_STATEMENT:
      state.Init(node_val.getForStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::WHILE_STATEMENT:
      state.Init(node_val.getWhileStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::DO_WHILE_STATEMENT:
      state.Init(node_val.getDoWhileStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::SWITCH_STATEMENT:
      state.Init(node_val.getSwitchStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::EXPRESSION_STATEMENT:
      state.Init(node_val.getExpressionStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::FOR_IN_STATEMENT:
      state.Init(node_val.getForInStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::FOR_OF_STATEMENT:
      state.Init(node_val.getForOfStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::BLOCK:
      state.Init(node_val.getBlock(), this);
      break;
    case ::Ast::Statement::NodeVal::EMPTY_STATEMENT:
      state.Init(node_val.getEmptyStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::CONTINUE_STATEMENT:
      state.Init(node_val.getContinueStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::BREAK_STATEMENT:
      state.Init(node_val.getBreakStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::RETURN_STATEMENT:
      state.Init(node_val.getReturnStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::WITH_STATEMENT:
      state.Init(node_val.getWithStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::TRY_CATCH_STATEMENT:
      state.Init(node_val.getTryCatchStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::TRY_FINALLY_STATEMENT:
      state.Init(node_val.getTryFinallyStatement(), this);
      break;
    case ::Ast::Statement::NodeVal::DEBUGGER_STATEMENT:
      break;
    case ::Ast::Statement::NodeVal::UNKNOWN_STATEMENT:
    default:
      UNREACHABLE();
  }

  statements_[label] = state.GetType();
}

void ConcolicExecutor::OnNewNode(const ::Ast::Declaration::Reader& reader) {}

void ConcolicExecutor::OnNewNode(const ::Ast::BlockNode::Reader& reader) {
  SymbolicStatement state;
  state.Init(reader.getBlock(), this);
}

void ConcolicExecutor::OnNewNode(
    const ::Ast::FunctionLiteralNode::Reader& reader) {
  MakeExpression(reader, new DummyExpressionSlot());
}


class VariableSymbolicExecutor : public SymbolicExecutor {
public:
  virtual std::shared_ptr<SymbolicState> StaticValue(
      const SymbolicFactory& fact,
      ExpressionSlot* owner) {
    return fact.Undefined();
  }
};


void ConcolicExecutor::OnNewNode(
    const ::Ast::VariableProxyNode::Reader& reader) {
  MakeExpression(reader, new VariableSymbolicExecutor());
}

void ConcolicExecutor::OnNewNode(const ::Ast::CaseClause::Reader& reader) {
  MakeExpression(reader, new DummyExpressionSlot());
}

template <typename Reader>
void ConcolicExecutor::MakeExpression(
    Reader reader, SymbolicExecutor* new_exp) {
  NodeLabel key;
  DCHECK(builder_serializer_.Deserialize(reader.getNode().getLabel(), &key));
  DCHECK(nodes_.find(key) == nodes_.end());
  nodes_[key] = std::shared_ptr<ExpressionSlot>(
      new ExpressionSlot(this, key, new_exp));
}


ExpressionSlot::ExpressionSlot(
    ConcolicExecutor* context,
    NodeLabel label,
    std::vector<std::shared_ptr<ExpressionSlot>>&& deps,
    SymbolicExecutor* sym) :
  label_(label),
  result_type_(ControlFlowState::NONE),
  depends_on_(std::move(deps)),
  context_(context),
  sym_(sym),
  feeds_other_(false) {
  for (auto& ref : depends_on_) {
    DCHECK(ref);
    ref->SetHasParent();
  }
}

ExpressionSlot::ExpressionSlot(
    ConcolicExecutor* context,
    NodeLabel label,
    SymbolicExecutor* sym) :
  label_(label),
  result_type_(ControlFlowState::NONE),
  depends_on_(),
  context_(context),
  sym_(sym),
  feeds_other_(false) {}

void ExpressionSlot::SetHasParent() {
  feeds_other_ = true;
}


void ExpressionSlot::SetControlFlowState(ControlFlowState val) {
  result_type_ = val;
}

void ExpressionSlot::PopSymbolicState() {
  return context_->CurrentFrame().Pop(shared_from_this());
}

std::shared_ptr<SymbolicState> ExpressionSlot::GetSymbolicState() {
  return context_->CurrentFrame().GetExpression(shared_from_this()).GetState();
}

SymbolicMemorySlot ExpressionSlot::HandleAssignment(
    const ExecutionInfo& info) {
  SymbolicFactory maker(context_->isolate(), info.GetEval(), label_);
  if (RecomputeHasSymbolicState()) {
    return SymbolicMemorySlot(true, sym_->OnAssignmentRValue(maker, this));
  } else {
    return CheckForTaint(maker, info.GetEval());
  }
}

SymbolicMemorySlot ExpressionSlot::CheckForTaint(
    const SymbolicFactory& maker, Handle<Object> eval) {
  // If we have a tainted object, then we kick off the symbolic execution
  // at this point

  TaintFlag flag = kTaintFlagUntainted;
  if (eval->IsString()) {
    DisallowHeapAllocation no_gc;
    flag = CheckTaint(String::cast(*eval));
  }
  if (flag != kTaintFlagUntainted) {
    return SymbolicMemorySlot(true, maker.MakeSymbolic());
  } else {
    return SymbolicMemorySlot(false, maker.FromLiteral());
  }
}

void ExpressionSlot::HandleVariableLoadExecution(
    const VariableLoadExecutionInfo& info) {
  SymbolicFactory maker(context_->isolate(), info.GetEval(), label_);

  #ifdef DEBUG
  if (info.GetSlot()) {
    DCHECK(info.GetSlot()->GetState()->DebugCheckObjectEquals(info.GetEval()));
  }
  #endif

  SymbolicMemorySlot new_state = MakeExec(maker, info);
  PopChildren();
  PushExecution(new_state, info);
}

void ExpressionSlot::PopChildren() {
  for (auto& dep : depends_on_) {
    dep->PopSymbolicState();
  }
}

SymbolicMemorySlot ExpressionSlot::MakeExec(
    const SymbolicFactory& maker, const VariableLoadExecutionInfo& info) {
  SymbolicMemorySlot* maybe_mem_slot = info.GetSlot();
  if (maybe_mem_slot) {
    if (maybe_mem_slot->HasSymbolicState()) {
      return *maybe_mem_slot;
    } else {
      return CheckForTaint(maker, info.GetEval());
    }
  } else {
    return CheckForTaint(maker, info.GetEval());
  }
}


class PropertyExpressionSlot : public SymbolicExecutor {
public:
  virtual void Init(::Ast::Property::Reader reader,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    *deps = {{ reader.getObj().getNode().getLabel(),
               reader.getKey().getNode().getLabel() }};
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    auto obj = slot->GetDep(OBJ)->GetSymbolicState();
    obj->ForceSerialization();
    return fact.GetProperty(obj,
                            slot->GetDep(KEY)->GetSymbolicState());
  }

  virtual void OnBeforeExecute(ExpressionSlot* slot) {
    auto& current_frame = slot->context()->CurrentFrame();
    current_frame.PrepareForPropertyGetterAccessorFrame(
        current_frame.GetExpression(slot->GetDep(OBJ)));
  }

  static const size_t OBJ = 0;
  static const size_t KEY = 1;
};


SymbolicMemorySlot ExpressionSlot::MakeExec(
    const SymbolicFactory& maker, const ExecutionInfo& info) {
  switch (info.GetCheckType()) {
    case EXPRESSION_AFTER_OPTIMIZED_OUT: {
      return SymbolicMemorySlot(false, maker.OptimizedOut());
    }
      break;

    case STATIC_VALUE_CHECK: {
      return SymbolicMemorySlot(
          false, sym_->StaticValue(maker, this));
    }
      break;

    case EXPRESSION_UNEXECUTED: {
      return SymbolicMemorySlot(false, maker.Unexecuted());
    }
      break;

    case EXPRESSION_LVALUE: {
      return SymbolicMemorySlot(false, maker.LValue());
    }
      break;

    case EXPRESSION_PROPERTY_LVALUE: {
      SymbolicStackFrame& current_frame = context_->CurrentFrame();
      SymbolicMemorySlot answer = current_frame.GetExpression(
          GetDep(PropertyExpressionSlot::KEY));
      current_frame.PrepareForPropertyAssignmentKey(
          current_frame.GetExpression(GetDep(PropertyExpressionSlot::OBJ)),
          answer);
      return answer;
    }
      break;

    case EXPRESSION_AFTER: {
      if (RecomputeHasSymbolicState()) {
        return SymbolicMemorySlot(
            true, sym_->SymbolicExecuteSelf(maker, this));
      } else {
        return CheckForTaint(maker, info.GetEval());
      }
    }
      break;

    default:
      UNREACHABLE();
      break;
  }
}


void ExpressionSlot::HandleExecution(const ExecutionInfo& info) {
  if (info.GetCheckType() == EXPRESSION_BEFORE) {
    sym_->OnBeforeExecute(this);
    return;
  }

  SymbolicFactory maker(context_->isolate(), info.GetEval(), label_);
  SymbolicMemorySlot push_state = MakeExec(maker, info);
  PushExecution(push_state, info);
  switch (info.GetCheckType()) {
    case STATIC_VALUE_CHECK:
    case EXPRESSION_UNEXECUTED:
    case EXPRESSION_PROPERTY_LVALUE:
      break;

    default:
      PopChildren();
      break;
  }
}

void ExpressionSlot::PushExecution(
    SymbolicMemorySlot push_state, const ExecutionInfo& info) {
  DCHECK_NOT_NULL(push_state.GetState().get());

  SymbolicStackFrame& current_frame = context_->CurrentFrame();

  std::shared_ptr<SymbolicState> property_lookup =
    context_->LookupObjectProperties(info.GetEval());
  if (property_lookup) {
    // We merge the two states, preferring to use the property lookup if we
    // don't have any symbolic information in the execution.
    push_state = SymbolicMemorySlot(
        true,
        push_state.HasSymbolicState()
        ? SymbolicState::MergeWith(property_lookup,
                                   push_state.GetState(),
                                   SymbolicState::MergeType::PROPERTY,
                                   context_->isolate())
        : property_lookup);
  }

  switch (info.GetCheckType()) {
    case EXPRESSION_LVALUE:
    case EXPRESSION_PROPERTY_LVALUE:
      break;

    default:
      push_state = current_frame.Execute(
          shared_from_this(), push_state, feeds_other_);
      break;
  }

  switch (preparation_state_) {
    case LEFT_OF_BINARY_PLUS:
      current_frame.PrepareForImplicitStringConversion(
          push_state, TO_STRING_CONVERT_PLUS_LEFT);
      break;

    case RIGHT_OF_BINARY_PLUS:
      current_frame.PrepareForImplicitStringConversion(
          push_state, TO_STRING_CONVERT_PLUS_RIGHT);
      break;

    case NO_PREPARATION:
      break;
  }

  if (push_state.HasSymbolicState()) {
    switch (result_type_) {
      case BRANCH:
        context_->TookBranch(
            push_state.GetState(), info.GetEval()->BooleanValue());
        break;

      case JUMP:
        context_->TookJump(push_state.GetState());
        break;

      case THROWABLE:
        current_frame.PrepareForThrow(push_state);
        break;

      case NONE:
        break;

      case SWITCH_TAG:
        context_->TookSwitch(push_state.GetState());
        break;

      case ITERATOR_STATE:
        context_->TookIterator(push_state.GetState());
        break;

      default:
        UNREACHABLE();
    }
  }
}

void ExpressionSlot::SetIsLeftOfBinaryPlus() {
  preparation_state_ = LEFT_OF_BINARY_PLUS;
}

void ExpressionSlot::SetIsRightOfBinaryPlus() {
  preparation_state_ = RIGHT_OF_BINARY_PLUS;
}


bool ExpressionSlot::RecomputeHasSymbolicState() {
  bool ret = false;
  SymbolicStackFrame& curr_frame = context_->CurrentFrame();
  for (auto& dep : depends_on_) {
    DCHECK(dep);
    ret |= curr_frame.GetExpression(dep).HasSymbolicState();
  }
  return ret;
}

std::shared_ptr<ExpressionSlot>
ExpressionSlot::GetDep(size_t i) const {
  return depends_on_[i];
}

size_t ExpressionSlot::NumDeps() const {
  return depends_on_.size();
}


class BinaryExpressionSlot : public SymbolicExecutor {
public:

  BinaryExpressionSlot() : operation_(::Ast::Token::UNKNOWN) {}

  virtual void Init(::Ast::BinaryOperation::Reader node,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    *deps = {{ node.getLeft().getNode().getLabel(),
               node.getRight().getNode().getLabel() }};
    operation_ = node.getToken();
  }

  virtual void InitSlot(ExpressionSlot* slot) {
    if (IsLogical()) {
      // Short circuit operators affect the control flow.
      slot->GetDep(LEFT)->SetControlFlowState(
          ExpressionSlot::ControlFlowState::BRANCH);
    } else if (operation_ == ::Ast::Token::ADD) {
      slot->GetDep(LEFT)->SetIsLeftOfBinaryPlus();
      slot->GetDep(RIGHT)->SetIsRightOfBinaryPlus();
    }
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    return fact.Operation(operation_,
                          slot->GetDep(LEFT)->GetSymbolicState(),
                          slot->GetDep(RIGHT)->GetSymbolicState());
  }

  bool IsLogical() {
    return operation_ == ::Ast::Token::AND || operation_ == ::Ast::Token::OR;
  }

private:
  ::Ast::Token operation_;

  static const int LEFT = 0;
  static const int RIGHT = 1;
};

class UnaryExpressionSlot : public SymbolicExecutor {
public:
  UnaryExpressionSlot() : operation_(::Ast::Token::UNKNOWN) {}

  virtual void Init(::Ast::UnaryOperation::Reader node,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    *deps = {{ node.getExpression().getNode().getLabel() }};
    operation_ = node.getToken();
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    return fact.Operation(operation_, slot->GetDep(EXPR)->GetSymbolicState());
  }

  virtual std::shared_ptr<SymbolicState> StaticValue(
      const SymbolicFactory& fact,
      ExpressionSlot* owner) {
    if (operation_ == ::Ast::Token::VOID) {
      return fact.Undefined();
    }
    UNREACHABLE();
  }

private:
  static const int EXPR = 0;

  ::Ast::Token operation_;
};

class CompareExpressionSlot : public SymbolicExecutor {
public:
  CompareExpressionSlot() : operation_(::Ast::Token::UNKNOWN) {}

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    return fact.Operation(
        operation_,
        slot->GetDep(LEFT)->GetSymbolicState(),
        slot->GetDep(RIGHT)->GetSymbolicState());
  }

  virtual void Init(::Ast::CompareOperation::Reader node,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    *deps = {{ node.getLeft().getNode().getLabel(),
               node.getRight().getNode().getLabel() }};
    operation_ = node.getToken();
  }

private:
  ::Ast::Token operation_;
  static const int LEFT = 0;
  static const int RIGHT = 1;
};


class ConditionalExpressionSlot : public SymbolicExecutor {
public:
  virtual void Init(::Ast::Conditional::Reader reader,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    *deps = {{ reader.getCond().getNode().getLabel(),
               reader.getThen().getNode().getLabel(),
               reader.getElse().getNode().getLabel() }};
  }

  virtual void InitSlot(ExpressionSlot* slot) {
    slot->GetDep(COND)->SetControlFlowState(
        ExpressionSlot::ControlFlowState::BRANCH);
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    return fact.IfThenElse(
        slot->GetDep(COND)->GetSymbolicState(),
        slot->GetDep(THEN)->GetSymbolicState(),
        slot->GetDep(ELSE)->GetSymbolicState());
  }

private:
  static const size_t COND = 0;
  static const size_t THEN = 1;
  static const size_t ELSE = 2;
};

class LiteralExpressionSlot : public SymbolicExecutor {
public:
  LiteralExpressionSlot(::Ast::Literal::Reader reader) :
    saved_literal_(new ::capnp::MallocMessageBuilder()) {
    saved_literal_->setRoot(reader.getObjectValue());
  }

  virtual std::shared_ptr<SymbolicState> StaticValue(
      const SymbolicFactory& fact, ExpressionSlot* owner) {
    return fact.FromAstLiteral(saved_literal_);
  }

private:
  std::shared_ptr<::capnp::MallocMessageBuilder> saved_literal_;
};

class CallExpressionSlot : public SymbolicExecutor {
public:

  virtual void Init(::Ast::Call::Reader reader,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    deps->push_back(reader.getExpression().getNode().getLabel());
    for (::Ast::Expression::Reader arg : reader.getArguments()) {
      deps->push_back(arg.getNode().getLabel());
    }
  }

  virtual void Init(::Ast::CallNew::Reader reader,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    deps->push_back(reader.getExpression().getNode().getLabel());
    for (::Ast::Expression::Reader arg : reader.getArguments()) {
      deps->push_back(arg.getNode().getLabel());
    }
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    std::vector<std::shared_ptr<SymbolicState>> sym_args;
    for (int i = 1; i < slot->NumDeps(); ++i) {
      sym_args.push_back(slot->GetDep(i)->GetSymbolicState());
    }
    return fact.CallNew(
        slot->GetDep(EXPR)->GetSymbolicState(), std::move(sym_args));
  }

  virtual void InitSlot(ExpressionSlot* slot) {
    slot->GetDep(EXPR)->SetControlFlowState(
        ExpressionSlot::ControlFlowState::JUMP);
  }

private:
  const static int EXPR = 0;
};

constexpr auto& RUNTIME_CALL_FN_NAME = "_Call";
static const int RUNTIME_CALL_TARGET_INDEX = 0;
static const int RUNTIME_CALL_RECEIVER_INDEX = 1;
static const int RUNTIME_CALL_NARGS = 2;


class CallRuntimeExpressionSlot : public SymbolicExecutor {
public:

  virtual void Init(::Ast::CallRuntime::Reader reader,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    auto fn = reader.getInfo().getFn();
    if (fn.which() == ::Ast::CallRuntime::RuntimeInfo::Fn::RUNTIME_FUNCTION) {
      has_context_index_ = false;
      name_ = fn.getRuntimeFunction().getName();
      needs_on_after_execute_ = (name_ == RUNTIME_CALL_FN_NAME);
    } else {
      DCHECK(fn.which() == ::Ast::CallRuntime::RuntimeInfo::Fn::CONTEXT_INDEX);
      has_context_index_ = true;
      context_index_ = fn.getContextIndex();
      needs_on_after_execute_ = false;
    }
    for (::Ast::Expression::Reader arg : reader.getArguments()) {
      deps->push_back(arg.getNode().getLabel());
    }
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    std::vector<std::shared_ptr<SymbolicState>> sym_args;
    for (int i = 0; i < slot->NumDeps(); ++i) {
      sym_args.push_back(slot->GetDep(i)->GetSymbolicState());
    }
    return has_context_index_
      ? fact.CallRuntime(context_index_, std::move(sym_args))
      : fact.CallRuntime(name_, std::move(sym_args));
  }

  virtual void OnBeforeExecute(ExpressionSlot* slot) {
    if (needs_on_after_execute_) {
      // We check if we have a call to Runtime_Call which requires setting up
      // the stack frame. See runtime-function.cc::Runtime_Call for the
      // expected arguments order.

      auto& current_frame = slot->context()->CurrentFrame();

      size_t number_of_args = slot->NumDeps();
      DCHECK_LE(RUNTIME_CALL_NARGS, number_of_args);

      // Target is first argument
      SymbolicMemorySlot target = current_frame.GetExpression(
          slot->GetDep(RUNTIME_CALL_TARGET_INDEX));

      // Receiver is second argument
      SymbolicMemorySlot receiver = current_frame.GetExpression(
          slot->GetDep(RUNTIME_CALL_RECEIVER_INDEX));

      // Rest arguments are for the target function
      std::vector<SymbolicMemorySlot> rest_args;
      for (size_t i = RUNTIME_CALL_NARGS; i < number_of_args; i++) {
        rest_args.push_back(current_frame.GetExpression(slot->GetDep(i)));
      }
      current_frame.PrepareForCallRuntimeCall(
          receiver, target, std::move(rest_args));
    }
  }

private:

  bool has_context_index_;
  bool needs_on_after_execute_;
  std::string name_;
  int32_t context_index_;
};

class CountExpressionSlot : public SymbolicExecutor {
public:
  virtual void Init(::Ast::CountOperation::Reader reader,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    operation_ = reader.getOperation();
    is_postfix_ = reader.getIsPostfix();
    deps->push_back(reader.getExpression().getNode().getLabel());
  }

  virtual std::shared_ptr<SymbolicState> OnAssignmentRValue(
      const SymbolicFactory& fact,
      ExpressionSlot* slot) {
    return fact.Operation(
        operation_, slot->GetDep(EXPR)->GetSymbolicState());
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    auto unincremented = slot->GetDep(EXPR)->GetSymbolicState();
    if (is_postfix_) {
      return unincremented;
    } else {
      return fact.Operation(operation_, unincremented);
    }
  }

  virtual size_t LValueIndex() {
    return EXPR;
  }

private:
  ::Ast::Token operation_;
  bool is_postfix_;
  const static int EXPR = 0;
};

class AssignmentExpressionSlot : public SymbolicExecutor {
public:

  virtual std::shared_ptr<SymbolicState> OnAssignmentRValue(
      const SymbolicFactory& fact,
      ExpressionSlot* slot) {

    #ifdef DEBUG
    if (is_simple_) {
      DCHECK(fact.DebugCheckObjectEquals(
                 slot->GetDep(VALUE)->GetSymbolicState()));
    }
    #endif

    return SymbolicExecuteSelf(fact, slot);
  }

  virtual void Init(::Ast::Assignment::Reader reader,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    operation_ = reader.getOperation();
    is_simple_ = reader.getIsSimple();

    deps->push_back(reader.getValue().getNode().getLabel());
    if (!is_simple_) {
      deps->push_back(reader.getTarget().getNode().getLabel());
    }
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    return is_simple_
      ? slot->GetDep(VALUE)->GetSymbolicState()
      : fact.Operation(
          operation_,
          slot->GetDep(TARGET)->GetSymbolicState(),
          slot->GetDep(VALUE)->GetSymbolicState());
  }

private:
  ::Ast::Token operation_;
  bool is_simple_;

  const static int VALUE = 0;
  const static int TARGET = 1;
};

class ThrowExpressionSlot : public SymbolicExecutor {
public:
  virtual void Init(::Ast::Throw::Reader reader,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    deps->push_back(reader.getException().getNode().getLabel());
  }

  virtual void InitSlot(ExpressionSlot* slot) {
    slot->SetControlFlowState(
        ExpressionSlot::ControlFlowState::THROWABLE);
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    return slot->GetDep(THROWABLE)->GetSymbolicState();
  }

private:
  const static int THROWABLE = 0;
};


class ArrayLiteralExpressionSlot : public SymbolicExecutor {
public:
  ArrayLiteralExpressionSlot() : saved_literal_() {}
  ~ArrayLiteralExpressionSlot() {}

  virtual void Init(::Ast::ArrayLiteral::Reader reader,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    for (auto value : reader.getValues()) {
      deps->push_back(value.getNode().getLabel());
    }

    saved_literal_.reset(new ::capnp::MallocMessageBuilder());
    saved_literal_->initRoot<::Ast::JsObjectValue>().
      getValue().setAstArrayLiteral(reader);
  }

  virtual std::shared_ptr<SymbolicState> StaticValue(
      const SymbolicFactory& fact,
      ExpressionSlot* owner) {
    return fact.FromAstLiteral(saved_literal_);
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    std::vector<std::shared_ptr<SymbolicState>> values;
    for (int i = 0; i < slot->NumDeps(); i++) {
      values.push_back(slot->GetDep(i)->GetSymbolicState());
    }
    return fact.ArrayLiteral(std::move(values));
  }

private:
  std::shared_ptr<::capnp::MallocMessageBuilder> saved_literal_;
};


class ObjectLiteralExpressionSlot : public SymbolicExecutor {
public:
  ObjectLiteralExpressionSlot() : saved_literal_() {}
  ~ObjectLiteralExpressionSlot() {}

  virtual void Init(::Ast::ObjectLiteral::Reader reader,
                    std::vector<::Ast::NodeLabel::Reader>* deps) {
    for (auto property : reader.getProperties()) {
      deps->push_back(property.getKey().getNode().getLabel());
      deps->push_back(property.getValue().getNode().getLabel());
    }

    saved_literal_.reset(new ::capnp::MallocMessageBuilder());
    saved_literal_->initRoot<::Ast::JsObjectValue>().
      getValue().setAstObjectLiteral(reader);
  }

  virtual std::shared_ptr<SymbolicState> StaticValue(
      const SymbolicFactory& fact,
      ExpressionSlot* owner) {
    return fact.FromAstLiteral(saved_literal_);
  }

  virtual std::shared_ptr<SymbolicState> SymbolicExecuteSelf(
      const SymbolicFactory& fact, ExpressionSlot* slot) {
    std::vector<SymbolicKeyValue> values;
    DCHECK_EQ(0, slot->NumDeps() % 2);
    for (int i = 0; i < slot->NumDeps(); i += 2) {
      values.push_back(SymbolicKeyValue(
                           slot->GetDep(i)->GetSymbolicState(),
                           slot->GetDep(i + 1)->GetSymbolicState()));
    }
    return fact.ObjectLiteral(std::move(values));
  }

private:
  std::shared_ptr<::capnp::MallocMessageBuilder> saved_literal_;
};



template <typename T, typename Reader>
T* SymbolicExecutor::New(
    Reader reader,
    std::vector<::Ast::NodeLabel::Reader>* deps) {
  T* newexec = new T();
  newexec->Init(reader, deps);
  return newexec;
}


SymbolicStatement::SymbolicStatement() :
  type_(SymbolicStatement::Type::OTHER),
  depends_() {}


void ConcolicExecutor::Initialize() {
  object_manager_.Initialize();
}

std::shared_ptr<ExpressionSlot> ConcolicExecutor::NewSlot(
    const ::Ast::Expression::Reader& reader) {
  auto node_val = reader.getNodeVal();
  SymbolicExecutor* new_slot;
  NodeLabel node_label;
  CHECK(builder_serializer_.Deserialize(reader.getNode().getLabel(),
                                        &node_label));
  std::vector<::Ast::NodeLabel::Reader> deps;

  switch (node_val.which()) {
    case ::Ast::Expression::NodeVal::BINARY_OPERATION:
      new_slot = SymbolicExecutor::New<BinaryExpressionSlot>(
          node_val.getBinaryOperation(), &deps);
      break;
    case ::Ast::Expression::NodeVal::UNARY_OPERATION:
      new_slot = SymbolicExecutor::New<UnaryExpressionSlot>(
          node_val.getUnaryOperation(), &deps);
      break;
    case ::Ast::Expression::NodeVal::COMPARE_OPERATION:
      new_slot = SymbolicExecutor::New<CompareExpressionSlot>(
          node_val.getCompareOperation(), &deps);
      break;
    case ::Ast::Expression::NodeVal::CONDITIONAL:
      new_slot = SymbolicExecutor::New<ConditionalExpressionSlot>(
          node_val.getConditional(), &deps);
      break;
    case ::Ast::Expression::NodeVal::PROPERTY:
      new_slot = SymbolicExecutor::New<PropertyExpressionSlot>(
          node_val.getProperty(), &deps);
      break;
    case ::Ast::Expression::NodeVal::LITERAL:
      new_slot = new LiteralExpressionSlot(node_val.getLiteral());
      break;
    case ::Ast::Expression::NodeVal::CALL:
      new_slot = SymbolicExecutor::New<CallExpressionSlot>(
          node_val.getCall(), &deps);
      break;
    case ::Ast::Expression::NodeVal::ASSIGNMENT:
      new_slot = SymbolicExecutor::New<AssignmentExpressionSlot>(
          node_val.getAssignment(), &deps);
      break;
    case ::Ast::Expression::NodeVal::VARIABLE_PROXY:
      new_slot = new VariableSymbolicExecutor();
      break;
    case ::Ast::Expression::NodeVal::CALL_NEW:
      new_slot = SymbolicExecutor::New<CallExpressionSlot>(
          node_val.getCallNew(), &deps);
      break;
    case ::Ast::Expression::NodeVal::CALL_RUNTIME:
      new_slot = SymbolicExecutor::New<CallRuntimeExpressionSlot>(
          node_val.getCallRuntime(), &deps);
      break;
    case ::Ast::Expression::NodeVal::THROW:
      new_slot = SymbolicExecutor::New<ThrowExpressionSlot>(
          node_val.getThrow(), &deps);
      break;
    case ::Ast::Expression::NodeVal::ARRAY_LITERAL:
      new_slot = SymbolicExecutor::New<ArrayLiteralExpressionSlot>(
          node_val.getArrayLiteral(), &deps);
      break;
    case ::Ast::Expression::NodeVal::OBJECT_LITERAL:
      new_slot = SymbolicExecutor::New<ObjectLiteralExpressionSlot>(
          node_val.getObjectLiteral(), &deps);
      break;
    default:
      new_slot = new DummyExpressionSlot();
      break;
  }

  std::vector<std::shared_ptr<ExpressionSlot>> expr_deps;
  for (auto& reader : deps) {
    expr_deps.push_back(SlotFor(reader));
  }

  ExpressionSlot* ret = new ExpressionSlot(
      this, node_label, std::move(expr_deps), new_slot);
  new_slot->InitSlot(ret);
  return std::shared_ptr<ExpressionSlot>(ret);
}



void ConcolicExecutor::OnRuntimeHookVariableContextStore(
    v8::internal::Handle<v8::internal::Object> concrete,
    v8::internal::Handle<v8::internal::Object> label,
    v8::internal::Handle<v8::internal::Context> context,
    v8::internal::Handle<v8::internal::Smi> ctx_idx) {
  ExecutionInfo info (concrete, EXPRESSION_VARIABLE_STORE_CONTEXT);
  NodeLabel slot_label;
  DCHECK(v8_serializer_.Deserialize(label, &slot_label));
  int idx = ctx_idx->value();
  DCHECK_LT(idx, context->length());
  DebugPrintTraceHook(slot_label, info);
  Handle<Object> serialized_label = mem_serializer_.Serialize(
      SlotFor(slot_label)->HandleAssignment(info));
  context->set(idx, *serialized_label);
}

void ConcolicExecutor::OnRuntimeParameterToContextStorage(
      int parameter_index,
      int context_slot_index,
      v8::internal::Handle<v8::internal::Context> context) {
  SymbolicStackFrame& current_frame = CurrentFrame();
  SymbolicMemorySlot param_sym =
    parameter_index == -1
    ? (current_frame.HasReceiver()
       ? current_frame.GetReceiver()
       : SymbolicMemorySlot(
           false,
           SymbolicFactory(isolate_).Uninstrumented(SymbolicFactory::RECEIVER)))
    : current_frame.GetArgument(parameter_index);

  DCHECK_LT(context_slot_index, context->length());
  context->set(context_slot_index, *(mem_serializer_.Serialize(param_sym)));
}


void ConcolicExecutor::RuntimePrepareApplyFrame(
    v8::internal::Handle<v8::internal::Object> argument_list,
    v8::internal::Handle<v8::internal::Object> target_fn,
    v8::internal::Handle<v8::internal::Object> new_target,
    v8::internal::Handle<v8::internal::Object> this_argument,
    FrameType caller_frame) {
  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    std::cerr << "preparing apply frame from caller "
              << FrameTypeToString(caller_frame) << "\n";
  }
  #endif  // DEBUG

  PrepareSymbolicStackFrame(FrameType::BUILTIN_APPLY);

  {
    SymbolicStackFrame& current_frame = CurrentFrame();

    switch (caller_frame) {
      // These states should match the states in builtins-x64.cc

      case FrameType::BUILTIN_FUNCTION_PROTOTYPE_APPLY: {
        // State
        // -----
        // Arg 0: this_argument
        // Arg 1: argument_list (optional)
        //
        // Receiver: target_function (May be any object)

        current_frame.AddArgumentToPreparingFrame(current_frame.GetArgument(1));
        current_frame.AddArgumentToPreparingFrame(current_frame.GetReceiver());
        current_frame.AddArgumentToPreparingFrame(
            SymbolicMemorySlot(false, SymbolicFactory(isolate_).Undefined()));
        current_frame.AddArgumentToPreparingFrame(current_frame.GetArgument(0));
      }
        break;

      case FrameType::BUILTIN_REFLECT_CONSTRUCT:
      case FrameType::BUILTIN_REFLECT_APPLY: {
        // State
        // -----
        // Arg 0: target_function
        // Arg 1: this_argument
        // Arg 2: argument_list
        // Arg 3: new.target (optional)
        //
        // Receiver: receiver (unused)

        current_frame.AddArgumentToPreparingFrame(current_frame.GetArgument(2));
        current_frame.AddArgumentToPreparingFrame(current_frame.GetArgument(0));
        current_frame.AddArgumentToPreparingFrame(current_frame.GetArgument(3));
        current_frame.AddArgumentToPreparingFrame(current_frame.GetArgument(1));
      }
        break;

      default:
        UNREACHABLE();
        break;
    }
  }


  // We enforce this state for the builtin Apply, because the builtin apply does
  // not have the typical calling convention.
  //
  // State
  // -----
  // Arg 0: argument_list
  // Arg 1: target_function
  // Arg 2: new.target (constructor or undefined)
  // Arg 3: this_argument
  //
  // Receiver: empty
  EnterSymbolicStackFrame();

  // Check that the state is what we expect
  #ifdef DEBUG
  DCHECK(CurrentFrame().GetArgument(0).
         GetState()->DebugCheckObjectEquals(argument_list));
  DCHECK(CurrentFrame().GetArgument(1).
         GetState()->DebugCheckObjectEquals(target_fn));
  DCHECK(CurrentFrame().GetArgument(2).
         GetState()->DebugCheckObjectEquals(new_target));
  DCHECK(CurrentFrame().GetArgument(3).
         GetState()->DebugCheckObjectEquals(this_argument));
  #endif  // DEBUG
}


bool TryHandleBoundFunction(
    v8::internal::Isolate* isolate,
    SymbolicStackFrame& current_frame,
    v8::internal::Handle<v8::internal::Object> maybe_bound_fn) {
  if (!maybe_bound_fn->IsJSBoundFunction()) {
    return false;
  }

  Handle<JSBoundFunction> target_fn =
    Handle<JSBoundFunction>::cast(maybe_bound_fn);

  SymbolicFactory factory (
      isolate, handle(target_fn->bound_this(), isolate));
  auto receiver_state = factory.FromLiteral();
  receiver_state->AddComment("from bound function");
  current_frame.SetReceiverOnPreparingFrame(
      SymbolicMemorySlot(false, receiver_state));

  Handle<FixedArray> bound_args = handle(
      target_fn->bound_arguments(), isolate);
  int len = bound_args->length();
  for (int i = 0; i < len; i++) {
    factory.SetConcrete(handle(bound_args->get(i), isolate));
    auto arg_state = factory.FromLiteral();
    arg_state->AddComment("from bound function");
    current_frame.AddArgumentToPreparingFrame(
        SymbolicMemorySlot(false, arg_state));
  }

  return true;
}


void ConcolicExecutor::RuntimePrepareCallFrame(
    v8::internal::Handle<v8::internal::Object> target_fn,
    FrameType caller_frame_type,
    v8::internal::Handle<v8::internal::FixedArray> args) {
  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    std::cerr << "preparing call frame from caller "
              << FrameTypeToString(caller_frame_type) << "\n";
  }
  #endif  // DEBUG


  PrepareSymbolicStackFrame(FrameType::BUILTIN_CALL);


  {
    SymbolicStackFrame& current_frame = CurrentFrame();

    // Check if we are dealing with a bound function
    bool needs_receiver = !TryHandleBoundFunction(
        isolate_, current_frame, target_fn);

    switch (caller_frame_type) {
      // State should match builtins-x64.cc

      case FrameType::BUILTIN_FUNCTION_PROTOTYPE_APPLY: {
        // State
        // -----
        // Arg 0: this_argument
        // Arg 1: argument_list (should be empty because Builtins::Call is only
        // called in prototype apply when the argument list is empty).
        //
        // Receiver: target_function

        if (needs_receiver) {
          current_frame.SetReceiverOnPreparingFrame(current_frame.GetArgument(0));
        }
        DCHECK(0 == args->length() || args->length() == 1);


        // Check that the state is what we expect
#ifdef DEBUG

        if (!target_fn->IsJSBoundFunction()) {
          // The first argument in args is the target function
          DCHECK_EQ(CurrentFrame().NumArgs(), args->length());
          for (size_t i = 0; i < args->length(); i++) {
            CurrentFrame().GetArgument(i).GetState()->DebugCheckObjectEquals(
                handle(args->get(i), isolate_));

            if (FLAG_taint_tracking_trace_concolic) {
              std::cerr << "Argument " << i << " of " << args->length() << "\n";
              args->get(i)->ShortPrint(std::cerr);
              std::cerr << "\n";
            }
          }
        }

#endif  // DEBUG

      }
        break;

      case FrameType::BUILTIN_FUNCTION_PROTOTYPE_CALL: {
        // State
        // -----
        // Arg 0: this_argument
        // Arg 1: argument 0 in new call
        // Arg n: argument n - 1 in new call
        //
        // Receiver : target_function

        SymbolicMemorySlot jump_target = current_frame.GetReceiver();
        if (jump_target.HasSymbolicState()) {
          auto target_state = jump_target.GetState();
          target_state->AddComment("Function.prototype.call setup");
          TookJump(target_state);
        }

        // Setup the frame
        if (needs_receiver) {
          current_frame.SetReceiverOnPreparingFrame(current_frame.GetArgument(0));
        }
        DCHECK(current_frame.NumArgs() == args->length() ||
               current_frame.NumArgs() == 0);
        uint32_t num_args = current_frame.NumArgs();
        for (size_t i = 1; i < num_args; i++) {
          current_frame.AddArgumentToPreparingFrame(
              current_frame.GetArgument(i));
        }
      }
        break;

      default:
        UNREACHABLE();
        break;
    }
  }

  // We enforce this state for Builtin::Call to match what the next stack frame
  // should look like.
  //
  // State
  // -----
  // Arg 0    : Argument 0 to target
  // ...
  // Arg n    : Argument n to target
  // Receiver : Receiver for the target_function

  EnterSymbolicStackFrame();
}

void ConcolicExecutor::RuntimePrepareCallOrConstructFrame(
    v8::internal::Handle<v8::internal::Object> target_fn,
    v8::internal::Handle<v8::internal::Object> new_target,
    v8::internal::Handle<v8::internal::FixedArray> args) {
  #ifdef DEBUG
  if (FLAG_taint_tracking_trace_concolic) {
    std::cerr << "preparing callorconstruct frame\nnew_target:\n";
    new_target->ShortPrint(std::cerr);
    std::cerr << "\n";
  }
  #endif  // DEBUG


  // This state must match the end of the prepare for RuntimePrepareApplyFrame
  //
  // State
  // -----
  // Arg 0: argument_list
  // Arg 1: target_function
  // Arg 2: new.target (constructor or undefined)
  // Arg 3: this_argument
  //
  // Receiver: empty

  bool needs_receiver;
  SymbolicStackFrame& current_frame = CurrentFrame();
  if (new_target->IsUndefined(isolate_)) {

    PrepareSymbolicStackFrame(FrameType::BUILTIN_CALL);

    needs_receiver = !TryHandleBoundFunction(
        isolate_, current_frame, target_fn);

    // We are dropping the new.target and setting up a Builtins::Call stack
    // frame.

    // This state must match the state set up by RuntimePrepareCallFrame call
    //
    // State
    // -----
    // Arg 0    : Argument 0 to target
    // ...
    // Arg n    : Argument n to target
    //
    // Receiver : Receiver for the target_function
  } else {

    PrepareSymbolicStackFrame(FrameType::BUILTIN_CONSTRUCT);

    SymbolicFactory receiver_fact (isolate_, new_target);
    current_frame.SetReceiverOnPreparingFrame(
        SymbolicMemorySlot(false, receiver_fact.FromLiteral()));
  }

  SymbolicMemorySlot target_function = current_frame.GetArgument(1);
  if (target_function.HasSymbolicState()) {
    auto target_fn_sym_state = target_function.GetState();
    target_fn_sym_state->AddComment("jumped from apply");
    TookJump(target_fn_sym_state);
  }


  SymbolicMemorySlot symbolic_argument_list = current_frame.GetArgument(0);
  SymbolicFactory factory (isolate_);
  for (size_t i = 0; i < args->length(); i++) {
    factory.SetConcrete(handle(args->get(i), isolate_));

    if (symbolic_argument_list.HasSymbolicState()) {
      SymbolicFactory idx_factory (
          isolate_, handle(Smi::FromInt(i), isolate_));
      std::shared_ptr<SymbolicState> state =
        factory.GetProperty(symbolic_argument_list.GetState(),
                            idx_factory.FromLiteral());
      state->AddComment("from builtin_apply arguments list");
      current_frame.AddArgumentToPreparingFrame(
          SymbolicMemorySlot(true, state));

    } else {
      current_frame.AddArgumentToPreparingFrame(
          SymbolicMemorySlot(false, factory.FromLiteral()));
    }
  }

  if (needs_receiver) {
    current_frame.SetReceiverOnPreparingFrame(current_frame.GetArgument(3));
  }

  EnterSymbolicStackFrame();
}



Handle<Object> ConcolicExecutor::OnRuntimeHookVariableStore(
    Handle<Object> value,
    Handle<Object> label,
    CheckType checktype,
    Handle<Object> var_index_or_holder) {
  ExecutionInfo info(value, checktype);
  NodeLabel node_label;
  DCHECK(v8_serializer_.Deserialize(label, &node_label));
  std::shared_ptr<ExpressionSlot> expr_slot = SlotFor(node_label);
  DebugPrintTraceHook(node_label, info);
  SymbolicMemorySlot rvalue_info (expr_slot->HandleAssignment(info));
  switch (checktype) {
    case CheckType::EXPRESSION_VARIABLE_STORE_CONTEXT:
      UNREACHABLE();
      break;

    case CheckType::EXPRESSION_VARIABLE_STORE: {
      DCHECK(var_index_or_holder->IsSmi());
      int var_index = Smi::cast(*var_index_or_holder)->value();
      DCHECK_EQ(NO_VARIABLE_INDEX, var_index);
      return mem_serializer_.Serialize(rvalue_info);
    }

    case CheckType::EXPRESSION_PROPERTY_STORE: {
      SymbolicStackFrame& current_frame = CurrentFrame();
      SymbolicMemKeyValue key_value = current_frame.TakeAssignmentPropertyKey();
      current_frame.PrepareForPropertySetterAccessorFrame(
          key_value.GetValue(), rvalue_info);
      if (var_index_or_holder->IsJSReceiver()) {
        object_manager_.OnAssign(
            Handle<JSReceiver>::cast(var_index_or_holder),
            SymbolicMemKeyValue(key_value.GetKey(), rvalue_info));
      }

      return handle(isolate()->heap()->undefined_value(), isolate());
    }

    case CheckType::EXPRESSION_PARAMETER_STORE: {
      DCHECK(var_index_or_holder->IsSmi());
      int var_index = Smi::cast(*var_index_or_holder)->value();
      DCHECK_LE(0, var_index);
      CurrentFrame().AssignArgument(var_index, rvalue_info);
      return handle(isolate()->heap()->undefined_value(), isolate());
    }

    default:
      UNREACHABLE();
  }
}

void ConcolicExecutor::TookJump(std::shared_ptr<SymbolicState> state) {
  MessageHolder message;
  auto record = message.InitRoot();
  state->WriteSelf(record
                   .getMessage()
                   .initTaintedControlFlow()
                   .getConstraint()
                   .initJump(),
                   message);
  TaintTracker::Impl::LogToFile(isolate(), message);
}

void ConcolicExecutor::TookSwitch(std::shared_ptr<SymbolicState> tag) {
  MessageHolder message;
  auto record = message.InitRoot();
  tag->WriteSelf(record
                 .getMessage()
                 .initTaintedControlFlow()
                 .getConstraint()
                 .initSwitchTag(),
                 message);
  TaintTracker::Impl::LogToFile(isolate(), message);
}

void ConcolicExecutor::TookBranch(
    std::shared_ptr<SymbolicState> symbolic_result, bool actual_result) {
  MessageHolder message;
  auto constraint =
    message.InitRoot().getMessage().initTaintedControlFlow().getConstraint();
  symbolic_result->WriteSelf(actual_result
                               ? constraint.initAssertion()
                               : constraint.initAssertNot(),
                             message);
  TaintTracker::Impl::LogToFile(isolate(), message);
}

void ConcolicExecutor::TookIterator(
    std::shared_ptr<SymbolicState> symbolic_result) {
  MessageHolder message;
  symbolic_result->WriteSelf(
      message.InitRoot().getMessage()
      .initTaintedControlFlow().getConstraint().initIterator(),
      message);
  TaintTracker::Impl::LogToFile(isolate(), message);
}


class AstSerializer : public AstVisitor<AstSerializer> {
public:

  AstSerializer(Isolate* isolate, ConcolicExecutor& exec) :
    current_(),
    isolate_(isolate),
    indexer_(exec),
    labeler_(isolate) {
    DCHECK_NOT_NULL(isolate);
    InitializeAstVisitor(isolate);
  }

  virtual ~AstSerializer() {}

  void Start(FunctionLiteral* node, ::Ast::Builder builder) {
    auto root = builder.initRoot();
    HandleFunctionLiteral(node, root.initFunc());
    InitNodeInfo(node, root.initNode());
    FinalizeNode(node, root);
    root.setEndPosition(node->end_position());
    root.setFunctionTokenPosition(node->function_token_position());
  }

private:

  class AstNodeBuilder {
  public:
    AstNodeBuilder(::Ast::Expression::Builder* expr) :
      is_expr_(State::EXPRESSION) {
      val_.expr_ = expr;
    }

    AstNodeBuilder(::Ast::Statement::Builder* statement) :
      is_expr_(State::STATEMENT) {
      val_.statement_ = statement;
    }

    AstNodeBuilder(::Ast::Declaration::Builder* decl) :
      is_expr_(State::DECLARATION) {
      val_.decl_ = decl;
    }

    AstNodeBuilder() : is_expr_(State::UNINITIALIZED) {
      val_.expr_ = nullptr;
    }

    ::Ast::Expression::Builder AsExpression() {
      DCHECK_EQ(State::EXPRESSION, is_expr_);
      return *(val_.expr_);
    }

    ::Ast::Statement::Builder AsStatement() {
      DCHECK_EQ(State::STATEMENT, is_expr_);
      return *(val_.statement_);
    }

    ::Ast::Declaration::Builder AsDeclaration() {
      return *(val_.decl_);
    }

  private:

    enum State {
      UNINITIALIZED,
      EXPRESSION,
      STATEMENT,
      DECLARATION
    };

    State is_expr_;

    union Value {
      ::Ast::Expression::Builder* expr_;
      ::Ast::Statement::Builder* statement_;
      ::Ast::Declaration::Builder* decl_;
    } val_;
  };

  // TODO: replace macros with function calls
  #define DO_VISIT_EXPRESSION(NODE, GET, BUILDER)          \
    SetupRecursiveVisit(NODE->GET(), BUILDER);

  #define DO_VISIT_STATEMENT(NODE, GET, BUILDER)          \
    SetupRecursiveVisit(NODE->GET(), BUILDER);

  template <typename Ast, typename Builder>
  void FinalizeNode(Ast* node, Builder builder) {
    InitNodeInfo(node, builder.initNode());
    #ifdef DEBUG
    NodeLabel label_check;
    BuilderSerializer sr;
    DCHECK(sr.Deserialize(builder.getNode().getLabel(), &label_check));
    DCHECK(label_check.IsValid());
    #endif

    if (FLAG_taint_tracking_enable_concolic) {
      indexer_.OnNewNode(builder.asReader());
    }
  }

  void InitNodeInfo(AstNode* node, ::Ast::NodeInfo::Builder builder) {
    NodeLabel node_label = labeler_.New();
    CHECK(serializer_.Serialize(builder.initLabel(), node_label));
    builder.setPosition(node->position());
    node->SetTaintTrackingLabel(node_label);
  }

  template <typename ExprOrSt, typename Builder>
  void SetupRecursiveVisit(ExprOrSt* node, Builder builder) {
    DCHECK_NOT_NULL(node);
    current_ = AstNodeBuilder(&builder);

    Visit(node);
    FinalizeNode(node, builder);
  }

  DEFINE_AST_REWRITER_SUBCLASS_MEMBERS();

  virtual void VisitVariableDeclaration(VariableDeclaration* node) {
    HandleDeclaration(
        node, current_.AsDeclaration().getNodeVal().getVariableDeclaration());
  }

  virtual void VisitFunctionDeclaration(FunctionDeclaration* node) {
    HandleFunctionDeclaration(
        node,
        current_.AsDeclaration().getNodeVal().initFunctionDeclaration());
  }

  void HandleFunctionDeclaration(
      FunctionDeclaration* node,
      ::Ast::FunctionDeclaration::Builder fndecl) {
    HandleDeclaration(node, fndecl.initDeclaration());
    HandleFunctionLiteralNode(node->fun(), fndecl.initFunctionLiteral());
  }

  virtual void VisitFunctionLiteral(FunctionLiteral* node) {
    HandleFunctionLiteral(
        node, current_.AsExpression().getNodeVal().initFunctionLiteral());
  }

  void HandleFunctionLiteralNode(
      FunctionLiteral* node, ::Ast::FunctionLiteralNode::Builder fnlit) {
    HandleFunctionLiteral(node, fnlit.initFunc());
    FinalizeNode(node, fnlit);
    fnlit.setEndPosition(node->end_position());
    fnlit.setFunctionTokenPosition(node->function_token_position());
  }

  void HandleFunctionLiteral(
      FunctionLiteral* node, ::Ast::FunctionLiteral::Builder fnlit) {
    DCHECK_NOT_NULL(node);

    switch(node->function_type()) {
      case FunctionLiteral::FunctionType::kAnonymousExpression:
        fnlit.setFunctionType(
            ::Ast::FunctionLiteral::FunctionType::ANONYMOUS_EXPRESSION);
        break;
      case FunctionLiteral::FunctionType::kNamedExpression:
        fnlit.setFunctionType(
            ::Ast::FunctionLiteral::FunctionType::NAMED_EXPRESSION);
        break;
      case FunctionLiteral::FunctionType::kDeclaration:
        fnlit.setFunctionType(
            ::Ast::FunctionLiteral::FunctionType::DECLARATION);
        break;
      case FunctionLiteral::FunctionType::kAccessorOrMethod:
        fnlit.setFunctionType(
            ::Ast::FunctionLiteral::FunctionType::ACCESSOR_OR_METHOD);
        break;
      default:
        UNREACHABLE();
    }
    switch(node->kind()) {
      case FunctionKind::kNormalFunction:
        fnlit.setFunctionKind(::Ast::FunctionKind::NORMAL_FUNCTION);
        break;
      case FunctionKind::kArrowFunction:
        fnlit.setFunctionKind(::Ast::FunctionKind::ARROW_FUNCTION);
        break;
      case FunctionKind::kGeneratorFunction:
        fnlit.setFunctionKind(::Ast::FunctionKind::GENERATOR_FUNCTION);
        break;
      case FunctionKind::kConciseMethod:
        fnlit.setFunctionKind(::Ast::FunctionKind::CONCISE_METHOD);
        break;
      case FunctionKind::kConciseGeneratorMethod:
        fnlit.setFunctionKind(
            ::Ast::FunctionKind::CONCISE_GENERATOR_METHOD);
        break;
      case FunctionKind::kGetterFunction:
        fnlit.setFunctionKind(::Ast::FunctionKind::GETTER_FUNCTION);
        break;
      case FunctionKind::kSetterFunction:
        fnlit.setFunctionKind(::Ast::FunctionKind::SETTER_FUNCTION);
        break;
      case FunctionKind::kAccessorFunction:
        fnlit.setFunctionKind(::Ast::FunctionKind::ACCESSOR_FUNCTION);
        break;
      case FunctionKind::kDefaultBaseConstructor:
        fnlit.setFunctionKind(
            ::Ast::FunctionKind::DEFAULT_BASE_CONSTRUCTOR);
        break;
      case FunctionKind::kDefaultSubclassConstructor:
        fnlit.setFunctionKind(
            ::Ast::FunctionKind::DEFAULT_SUBCLASS_CONSTRUCTOR);
        break;
      case FunctionKind::kBaseConstructor:
        fnlit.setFunctionKind(::Ast::FunctionKind::BASE_CONSTRUCTOR);
        break;
      case FunctionKind::kSubclassConstructor:
        fnlit.setFunctionKind(
            ::Ast::FunctionKind::SUB_CLASS_CONSTRUCTOR);
        break;
      case FunctionKind::kAsyncFunction:
        fnlit.setFunctionKind(::Ast::FunctionKind::ASYNC_FUNCTION);
        break;
      case FunctionKind::kAsyncArrowFunction:
        fnlit.setFunctionKind(
            ::Ast::FunctionKind::ASYNC_ARROW_FUNCTION);
        break;
      case FunctionKind::kAsyncConciseMethod:
        fnlit.setFunctionKind(
            ::Ast::FunctionKind::ASYNC_CONCISE_METHOD);
        break;
      default:
        UNREACHABLE();
    }
    auto decl_scope = fnlit.initScope();
    DoHandleScope(node->scope(), decl_scope.initScope());
    ZoneList<Declaration*>* decls = node->scope()->declarations();
    if (decls != nullptr) {
      auto out_decl_list = decl_scope.initDeclarations(decls->length());
      for (int i = 0; i < decls->length(); i++) {
        auto out_declaration = out_decl_list[i];
        Declaration* in_decl = decls->at(i);
        auto out_decl_val = out_declaration.getNodeVal();
        if (in_decl->IsVariableDeclaration()) {
          HandleDeclaration(
              in_decl, out_decl_val.initVariableDeclaration());
        } else {
          DCHECK(in_decl->IsFunctionDeclaration());
          HandleFunctionDeclaration(
              in_decl->AsFunctionDeclaration(),
              out_decl_val.initFunctionDeclaration());
        }
        FinalizeNode(in_decl, out_declaration);
      }
    }

    ZoneList<Statement*>* body_node = node->body();
    if (body_node != nullptr) {
      auto out_body_nodes = fnlit.initBody(body_node->length());
      HandleStatementList(body_node, &out_body_nodes);
    }
  }

  ::Ast::VariableMode ToAstVariableMode(VariableMode mode) {
    switch (mode) {
      case VariableMode::VAR:
        return ::Ast::VariableMode::VAR;
        break;
      case VariableMode::CONST_LEGACY:
        return ::Ast::VariableMode::CONST_LEGACY;
        break;
      case VariableMode::LET:
        return ::Ast::VariableMode::LET;
        break;
      case VariableMode::IMPORT:
        return ::Ast::VariableMode::IMPORT;
        break;
      case VariableMode::CONST:
        return ::Ast::VariableMode::CONST;
        break;
      case VariableMode::TEMPORARY:
        return ::Ast::VariableMode::TEMPORARY;
        break;
      case VariableMode::DYNAMIC:
        return ::Ast::VariableMode::DYNAMIC;
        break;
      case VariableMode::DYNAMIC_GLOBAL:
        return ::Ast::VariableMode::DYNAMIC_GLOBAL;
        break;
      case VariableMode::DYNAMIC_LOCAL:
        return ::Ast::VariableMode::DYNAMIC_LOCAL;
        break;
      default:
        UNREACHABLE();
    }
  }

  void HandleDeclaration(
      Declaration* node, ::Ast::DeclarationInterface::Builder decl) {
    DCHECK_NOT_NULL(node);
    HandleVariableProxyNode(node->proxy(), decl.initProxy());
    decl.setMode(ToAstVariableMode(node->mode()));
    ReferenceScope(node->scope(), decl.initScope());
  }

  virtual void VisitDoWhileStatement(DoWhileStatement* node) {
    auto dowhile = current_.AsStatement().getNodeVal().initDoWhileStatement();
    DO_VISIT_EXPRESSION(node, cond, dowhile.initCond());
    DO_VISIT_STATEMENT(node, body, dowhile.initBody());
  }

  virtual void VisitWhileStatement(WhileStatement* node) {
    auto whileNode = current_.AsStatement().getNodeVal().initDoWhileStatement();
    DO_VISIT_EXPRESSION(node, cond, whileNode.initCond());
    DO_VISIT_STATEMENT(node, body, whileNode.initBody());
  }

  virtual void VisitForStatement(ForStatement* node) {
    auto forNode = current_.AsStatement().getNodeVal().initForStatement();
    if (node->cond() != nullptr) {
      DO_VISIT_EXPRESSION(node, cond, forNode.initCond());
    }

    if (node->init() != nullptr) {
      DO_VISIT_STATEMENT(node, init, forNode.initInit());
    }

    if (node->next() != nullptr) {
      DO_VISIT_STATEMENT(node, next, forNode.initNext());
    }

    DO_VISIT_STATEMENT(node, body, forNode.initBody());
  }

  virtual void VisitForInStatement(ForInStatement* node) {
    auto forNode = current_.AsStatement().getNodeVal().initForInStatement();
    DO_VISIT_STATEMENT(node, body, forNode.initBody());
    // Requires a variable or property here.
    DO_VISIT_EXPRESSION(node, each, forNode.initEach());
    DO_VISIT_EXPRESSION(node, subject, forNode.initSubject());
  }

  virtual void VisitContinueStatement(ContinueStatement* node) {
    current_.AsStatement().getNodeVal().initContinueStatement();
  }

  virtual void VisitBreakStatement(BreakStatement* node) {
    current_.AsStatement().getNodeVal().initBreakStatement();
  }

  virtual void VisitReturnStatement(ReturnStatement* node) {
    auto ret = current_.AsStatement().getNodeVal().initReturnStatement();
    DO_VISIT_EXPRESSION(node, expression, ret.initValue());
  }

  virtual void VisitCaseClause(CaseClause* node) {
    auto caseClause = current_.AsExpression().getNodeVal().initCaseClause();
    HandleCaseClause(node, &caseClause);
  }

  void HandleStatementList(
      ZoneList<Statement*>* statements,
      ::capnp::List<::Ast::Statement>::Builder* out_statements) {
    DCHECK_NOT_NULL(statements);

    for (int i = 0; i < statements->length(); i++) {
      SetupRecursiveVisit(statements->at(i), (*out_statements)[i]);
    }
  }

  void HandleCaseClause(
      CaseClause* node, ::Ast::CaseClause::Builder* outCase) {
    DCHECK_NOT_NULL(node);
    // Check default case
    outCase->setIsDefault(node->is_default());
    if (!node->is_default()) {
      DO_VISIT_EXPRESSION(node, label, outCase->initLabel());
    }
    ZoneList<Statement*>* statements = node->statements();
    auto out_statements = outCase->initStatements(statements->length());
    HandleStatementList(statements, &out_statements);
  }

  virtual void VisitBlock(Block* node) {
    HandleBlock(node, current_.AsStatement().getNodeVal().initBlock());
  }

  void HandleBlock(Block* node, ::Ast::Block::Builder out_block) {
    DCHECK_NOT_NULL(node);
    DoHandleScope(node->scope(), out_block.initScope());
    ZoneList<Statement*>* statements = node->statements();
    auto out_statements = out_block.initStatements(statements->length());
    HandleStatementList(statements, &out_statements);
  }

  virtual void VisitExpressionStatement(ExpressionStatement* node) {
    DO_VISIT_EXPRESSION(
        node,
        expression,
        current_
          .AsStatement()
          .getNodeVal()
          .initExpressionStatement()
          .initExpression());
  }

  virtual void VisitEmptyStatement(EmptyStatement* node) {
    current_.AsStatement().getNodeVal().initEmptyStatement();
  }

  virtual void VisitSloppyBlockFunctionStatement(
      SloppyBlockFunctionStatement* node) {
    Visit(node->statement());
  }

  virtual void VisitIfStatement(IfStatement* node) {
    auto ifst = current_.AsStatement().getNodeVal().initIfStatement();
    DO_VISIT_EXPRESSION(node, condition, ifst.initCond());
    DO_VISIT_STATEMENT(node, then_statement, ifst.initThen());
    DO_VISIT_STATEMENT(node, else_statement, ifst.initElse());
  }

  virtual void VisitWithStatement(WithStatement* node) {
    auto withst = current_.AsStatement().getNodeVal().initWithStatement();
    DoHandleScope(node->scope(), withst.initScope());
    DO_VISIT_EXPRESSION(node, expression, withst.initExpression());
    DO_VISIT_STATEMENT(node, statement, withst.initStatement());
  }

  virtual void VisitSwitchStatement(SwitchStatement* node) {
    auto switchst = current_.AsStatement().getNodeVal().initSwitchStatement();
    DO_VISIT_EXPRESSION(node, tag, switchst.initTag());
    ZoneList<CaseClause*>* cases = node->cases();
    auto out_case_list = switchst.initCaseClauses(cases->length());
    for (int i = 0; i < cases->length(); i++) {
      auto builder = out_case_list[i];
      CaseClause* clause = cases->at(i);
      HandleCaseClause(clause, &builder);
      FinalizeNode(clause, builder);
    }
  }

  virtual void VisitForOfStatement(ForOfStatement* node) {
    auto forofst = current_.AsStatement().getNodeVal().initForOfStatement();
    DO_VISIT_STATEMENT(node, body, forofst.initBody());
    auto variable = forofst.initIterator();
    HandleVariable(node->iterator(), &variable);
    DO_VISIT_EXPRESSION(node, assign_iterator, forofst.initAssignIterator());
    DO_VISIT_EXPRESSION(node, next_result, forofst.initNextResult());
    DO_VISIT_EXPRESSION(node, result_done, forofst.initResultDone());
    DO_VISIT_EXPRESSION(node, assign_each, forofst.initAssignEach());
  }

  void HandleVariable(Variable* variable, ::Ast::Variable::Builder* out_var) {
    DCHECK_NOT_NULL(variable);
    ReferenceScope(variable->scope(), out_var->initScope());

    HandleAstRawString(out_var->initName(), variable->raw_name());
    if (variable->is_function()) {
      out_var->setKind(::Ast::Variable::Kind::FUNCTION);
    } else if (variable->is_this()) {
      out_var->setKind(::Ast::Variable::Kind::THIS);
    } else if (variable->is_arguments()) {
      out_var->setKind(::Ast::Variable::Kind::ARGUMENTS);
    } else {
      out_var->setKind(::Ast::Variable::Kind::NORMAL);
    }

    out_var->setMode(ToAstVariableMode(variable->mode()));
    switch(variable->initialization_flag()) {
      case InitializationFlag::kNeedsInitialization:
        out_var->setInitializationFlag(
            ::Ast::InitializationFlag::NEEDS_INITIALIZATION);
        break;
      case InitializationFlag::kCreatedInitialized:
        out_var->setInitializationFlag(
            ::Ast::InitializationFlag::CREATED_INITIALIZED);
        break;
      default:
        UNREACHABLE();
    }
    switch(variable->location()) {
      case VariableLocation::UNALLOCATED:
        out_var->setLocation(::Ast::Variable::Location::UNALLOCATED);
        break;
      case VariableLocation::PARAMETER:
        out_var->setLocation(::Ast::Variable::Location::PARAMETER);
        break;
      case VariableLocation::LOCAL:
        out_var->setLocation(::Ast::Variable::Location::LOCAL);
        break;
      case VariableLocation::CONTEXT:
        out_var->setLocation(::Ast::Variable::Location::CONTEXT);
        break;
      case VariableLocation::GLOBAL:
        out_var->setLocation(::Ast::Variable::Location::GLOBAL);
        break;
      case VariableLocation::LOOKUP:
        out_var->setLocation(::Ast::Variable::Location::LOOKUP_SLOT);
        break;
      default:
        UNREACHABLE();
    }
  }

  void HandleBlockNode(Block* block, ::Ast::BlockNode::Builder builder) {
    HandleBlock(block, builder.initBlock());
    FinalizeNode(block, builder);
  }

  virtual void VisitTryCatchStatement(TryCatchStatement* node) {
    auto trycatch = current_.AsStatement().getNodeVal().initTryCatchStatement();
    DoHandleScope(node->scope(), trycatch.initScope());
    auto var_builder = trycatch.initVariable();
    HandleVariable(node->variable(), &var_builder);

    HandleBlockNode(node->catch_block(), trycatch.initCatchBlock());
    HandleBlockNode(node->try_block(), trycatch.initTryBlock());
  }

  virtual void VisitTryFinallyStatement(TryFinallyStatement* node) {
    auto tryfinal =
      current_.AsStatement().getNodeVal().initTryFinallyStatement();
    HandleBlockNode(node->finally_block(), tryfinal.initFinallyBlock());
    HandleBlockNode(node->try_block(), tryfinal.initTryBlock());
  }

  virtual void VisitDebuggerStatement(DebuggerStatement* node) {
    current_.AsStatement().getNodeVal().setDebuggerStatement();
  }

  virtual void VisitNativeFunctionLiteral(NativeFunctionLiteral* node) {
    auto native =
      current_.AsExpression().getNodeVal().initNativeFunctionLiteral();
    native.setName(node->name()->ToCString().get());
    native.setExtensionName(node->extension()->name());
  }

  virtual void VisitConditional(Conditional* node) {
    auto cond = current_.AsExpression().getNodeVal().initConditional();
    DO_VISIT_EXPRESSION(node, condition, cond.initCond());
    DO_VISIT_EXPRESSION(node, then_expression, cond.initThen());
    DO_VISIT_EXPRESSION(node, else_expression, cond.initElse());
  }

  virtual void VisitVariableProxy(VariableProxy* node) {
    HandleVariableProxy(
        node, current_.AsExpression().getNodeVal().initVariableProxy());
  }

  void HandleVariableProxyNode(
      VariableProxy* node, ::Ast::VariableProxyNode::Builder out) {
    HandleVariableProxy(node, out.initProxy());
    FinalizeNode(node, out);
  }

  void HandleVariableProxy(
      VariableProxy* node, ::Ast::VariableProxy::Builder out) {
    DCHECK_NOT_NULL(node);
    bool is_resolved = node->is_resolved();
    out.setIsResolved(is_resolved);
    out.setIsThis(node->is_this());
    out.setIsAssigned(node->is_assigned());
    out.setIsNewTarget(node->is_new_target());
    if (is_resolved) {
      auto var = out.getValue().initVar();
      HandleVariable(node->var(), &var);
    } else {
      HandleAstRawString(out.getValue().initName(), node->raw_name());
    }
  }

  virtual void VisitLiteral(Literal* node) {
    auto lit = current_.AsExpression().getNodeVal().initLiteral();
    auto obj = lit.initObjectValue();
    const AstValue* value = node->raw_value();
    if (value->IsString()) {
      HandleAstRawString(obj.getValue().initString(), value->AsString());
    } else if (value->IsSmi()) {
      obj.getValue().setSmi(value->AsSmi()->value());
    } else if (value->IsNumber()) {
      obj.getValue().setNumber(value->AsNumber());
    } else if (value->IsPropertyName()) {
      HandleAstRawString(obj.getValue().initSymbol().getKind().initName(),
                         value->AsString());
    } else if (value->IsFalse()) {
      obj.getValue().setBoolean(false);
    } else if (value->IsTrue()) {
      obj.getValue().setBoolean(true);
    } else if (value->IsUndefined()) {
      obj.getValue().setUndefined();
    } else if (value->IsTheHole()) {
      obj.getValue().setTheHole();
    } else if (value->IsNull()) {
      obj.getValue().setNullObject();
    } else if (value->GetType() == AstValue::Type::SYMBOL){
      auto jsstr = obj.getValue().initSymbol().getKind().initName();
      const char* name = value->AsSymbolName();
      auto segments = jsstr.initSegments(1);
      auto symval = segments[0];
      symval.setContent(::capnp::Data::Reader(
                            reinterpret_cast<const uint8_t*>(name),
                            strlen(name)));
      symval.setIsOneByte(true);
    } else {
      std::cerr << "Unreachable ast value of type"
                << value->GetType() << std::endl;
      UNREACHABLE();
    }
  }

  virtual void VisitRegExpLiteral(RegExpLiteral* node) {
    auto regex = current_.AsExpression().getNodeVal().initRegExpLiteral();
    HandleAstRawString(regex.initPattern(), node->raw_pattern());
    regex.setFlags(node->flags());
  }

  virtual void VisitObjectLiteral(ObjectLiteral* node) {
    auto objlit = current_.AsExpression().getNodeVal().initObjectLiteral();
    ZoneList<ObjectLiteralProperty*>* props = node->properties();
    auto out_props = objlit.initProperties(props->length());
    for (int i = 0; i < props->length(); i++) {
      HandleProperty(props->at(i), out_props[i]);
    }
  }

  void HandleProperty(
      ObjectLiteralProperty* node, ::Ast::LiteralProperty::Builder litprop) {
    DCHECK_NOT_NULL(node);
    ::Ast::LiteralProperty::Kind kind;
    switch(node->kind()) {
      case ObjectLiteralProperty::Kind::CONSTANT:
        kind = ::Ast::LiteralProperty::Kind::CONSTANT;
        break;
      case ObjectLiteralProperty::Kind::COMPUTED:
        kind = ::Ast::LiteralProperty::Kind::COMPUTED;
        break;
      case ObjectLiteralProperty::Kind::MATERIALIZED_LITERAL:
        kind = ::Ast::LiteralProperty::Kind::MATERIALIZED_LITERAL;
        break;
      case ObjectLiteralProperty::Kind::GETTER:
        kind = ::Ast::LiteralProperty::Kind::GETTER;
        break;
      case ObjectLiteralProperty::Kind::SETTER:
        kind = ::Ast::LiteralProperty::Kind::SETTER;
        break;
      case ObjectLiteralProperty::Kind::PROTOTYPE:
        kind = ::Ast::LiteralProperty::Kind::PROTOTYPE;
        break;
      default:
        UNREACHABLE();
    }
    litprop.setKind(kind);
    DO_VISIT_EXPRESSION(node, key, litprop.initKey());
    DO_VISIT_EXPRESSION(node, value, litprop.initValue());
    litprop.setIsComputedName(node->is_computed_name());
    litprop.setIsStatic(node->is_static());
  }

  void HandleExpressionList(
      ZoneList<Expression*>* exps,
      ::capnp::List<::Ast::Expression>::Builder builder) {
    DCHECK_NOT_NULL(exps);
    for (int i = 0; i < exps->length(); i++) {
      SetupRecursiveVisit(exps->at(i), builder[i]);
    }
  }

  virtual void VisitArrayLiteral(ArrayLiteral* node) {
    ZoneList<Expression*>* exps = node->values();
    auto arrlit = current_.AsExpression().getNodeVal().initArrayLiteral();
    HandleExpressionList(exps, arrlit.initValues(exps->length()));
  }

  ::Ast::Token ToAstToken(Token::Value op) {
    switch (op) {
      // Binary operators
      case Token::Value::COMMA:
        return ::Ast::Token::COMMA;
        break;
      case Token::Value::OR:
        return ::Ast::Token::OR;
        break;
      case Token::Value::AND:
        return ::Ast::Token::AND;
        break;
      case Token::Value::BIT_OR:
        return ::Ast::Token::BIT_OR;
        break;
      case Token::Value::BIT_XOR:
        return ::Ast::Token::BIT_XOR;
        break;
      case Token::Value::BIT_AND:
        return ::Ast::Token::BIT_AND;
        break;
      case Token::Value::SHL:
        return ::Ast::Token::SHL;
        break;
      case Token::Value::SAR:
        return ::Ast::Token::SAR;
        break;
      case Token::Value::SHR:
        return ::Ast::Token::SHR;
        break;
      case Token::Value::ROR:
        return ::Ast::Token::ROR;
        break;
      case Token::Value::ADD:
        return ::Ast::Token::ADD;
        break;
      case Token::Value::SUB:
        return ::Ast::Token::SUB;
        break;
      case Token::Value::MUL:
        return ::Ast::Token::MUL;
        break;
      case Token::Value::DIV:
        return ::Ast::Token::DIV;
        break;
      case Token::Value::MOD:
        return ::Ast::Token::MOD;
        break;
      case Token::Value::EXP:
        return ::Ast::Token::EXP;
        break;
      case Token::Value::ASSIGN:
        return ::Ast::Token::ASSIGN;
      case Token::Value::INIT:
        return ::Ast::Token::INIT;
      case Token::Value::INC:
        return ::Ast::Token::INC;
      case Token::Value::DEC:
        return ::Ast::Token::DEC;

        // Comparisons
      case Token::Value::EQ:
        return ::Ast::Token::EQ;
        break;
      case Token::Value::NE:
        return ::Ast::Token::NE;
        break;
      case Token::Value::EQ_STRICT:
        return ::Ast::Token::EQ_STRICT;
        break;
      case Token::Value::NE_STRICT:
        return ::Ast::Token::NE_STRICT;
        break;
      case Token::Value::LT:
        return ::Ast::Token::LT;
        break;
      case Token::Value::GT:
        return ::Ast::Token::GT;
        break;
      case Token::Value::LTE:
        return ::Ast::Token::LTE;
        break;
      case Token::Value::GTE:
        return ::Ast::Token::GTE;
        break;
      case Token::Value::INSTANCEOF:
        return ::Ast::Token::INSTANCEOF;
        break;
      case Token::Value::IN:
        return ::Ast::Token::IN;
        break;

      case Token::Value::ASSIGN_BIT_OR:
        return ::Ast::Token::ASSIGN_BIT_OR;
        break;
      case Token::Value::ASSIGN_BIT_XOR:
        return ::Ast::Token::ASSIGN_BIT_XOR;
        break;
      case Token::Value::ASSIGN_BIT_AND:
        return ::Ast::Token::ASSIGN_BIT_AND;
        break;
      case Token::Value::ASSIGN_SHL:
        return ::Ast::Token::ASSIGN_SHL;
        break;
      case Token::Value::ASSIGN_SAR:
        return ::Ast::Token::ASSIGN_SAR;
        break;
      case Token::Value::ASSIGN_SHR:
        return ::Ast::Token::ASSIGN_SHR;
        break;
      case Token::Value::ASSIGN_ADD:
        return ::Ast::Token::ASSIGN_ADD;
        break;
      case Token::Value::ASSIGN_SUB:
        return ::Ast::Token::ASSIGN_SUB;
        break;
      case Token::Value::ASSIGN_MUL:
        return ::Ast::Token::ASSIGN_MUL;
        break;
      case Token::Value::ASSIGN_DIV:
        return ::Ast::Token::ASSIGN_DIV;
        break;
      case Token::Value::ASSIGN_MOD:
        return ::Ast::Token::ASSIGN_MOD;
        break;
      case Token::Value::ASSIGN_EXP:
        return ::Ast::Token::ASSIGN_EXP;
        break;

        // Unary operators
      case Token::Value::NOT:
        return ::Ast::Token::NOT;
        break;
      case Token::Value::BIT_NOT:
        return ::Ast::Token::BIT_NOT;
        break;
      case Token::Value::DELETE:
        return ::Ast::Token::DELETE;
        break;
      case Token::Value::TYPEOF:
        return ::Ast::Token::TYPEOF;
        break;
      case Token::Value::VOID:
        return ::Ast::Token::VOID;
        break;
      default:
        std::cerr <<
          "Unreachable token value: " << Token::Name(op) << std::endl;
        UNREACHABLE();
    }
  }

  ::Ast::KeyedAccessStoreMode ToAstKeyedAccessStoreMode(
      KeyedAccessStoreMode mode) {
    switch (mode) {
      case KeyedAccessStoreMode::STANDARD_STORE:
        return ::Ast::KeyedAccessStoreMode::STANDARD_STORE;
        break;
      case KeyedAccessStoreMode::STORE_TRANSITION_TO_OBJECT:
        return ::Ast::KeyedAccessStoreMode::STORE_TRANSITION_TO_OBJECT;
        break;
      case KeyedAccessStoreMode::STORE_TRANSITION_TO_DOUBLE:
        return ::Ast::KeyedAccessStoreMode::STORE_TRANSITION_TO_DOUBLE;
        break;
      case KeyedAccessStoreMode::STORE_AND_GROW_NO_TRANSITION:
        return ::Ast::KeyedAccessStoreMode::STORE_AND_GROW_NO_TRANSITION;
        break;
      case KeyedAccessStoreMode::STORE_AND_GROW_TRANSITION_TO_OBJECT:
        return ::Ast::KeyedAccessStoreMode::STORE_AND_GROW_TRANSITION_TO_OBJECT;
        break;
      case KeyedAccessStoreMode::STORE_AND_GROW_TRANSITION_TO_DOUBLE:
        return ::Ast::KeyedAccessStoreMode::STORE_AND_GROW_TRANSITION_TO_DOUBLE;
        break;
      case KeyedAccessStoreMode::STORE_NO_TRANSITION_IGNORE_OUT_OF_BOUNDS:
        return
          ::Ast::KeyedAccessStoreMode::STORE_NO_TRANSITION_IGNORE_OUT_OF_BOUNDS;
        break;
      case KeyedAccessStoreMode::STORE_NO_TRANSITION_HANDLE_COW:
        return ::Ast::KeyedAccessStoreMode::STORE_NO_TRANSITION_HANDLE_COW;
        break;
      default:
        UNREACHABLE();
    }
  }

  virtual void VisitAssignment(Assignment* node) {
    auto assign = current_.AsExpression().getNodeVal().initAssignment();
    assign.setOperation(ToAstToken(node->op()));
    assign.setStoreMode(ToAstKeyedAccessStoreMode(node->GetStoreMode()));
    assign.setIsSimple(!node->is_compound());
    assign.setIsUninitializedField(node->IsUninitialized());

    DO_VISIT_EXPRESSION(node, target, assign.initTarget());
    DO_VISIT_EXPRESSION(node, value, assign.initValue());
  }

  virtual void VisitThrow(Throw* node) {
    auto throwst = current_.AsExpression().getNodeVal().initThrow();
    DO_VISIT_EXPRESSION(node, exception, throwst.initException());
  }

  virtual void VisitProperty(Property* node) {
    auto prop = current_.AsExpression().getNodeVal().initProperty();
    prop.setIsForCall(node->is_for_call());
    prop.setIsStringAccess(node->IsStringAccess());

    DO_VISIT_EXPRESSION(node, obj, prop.initObj());
    DO_VISIT_EXPRESSION(node, key, prop.initKey());
  }

  inline ::Ast::Call::CallType ToCallType(Call::CallType from_v8) {
    switch (from_v8) {
      case Call::POSSIBLY_EVAL_CALL:
        return ::Ast::Call::CallType::POSSIBLY_EVAL_CALL;
      case Call::GLOBAL_CALL:
        return ::Ast::Call::CallType::GLOBAL_CALL;
      case Call::LOOKUP_SLOT_CALL:
        return ::Ast::Call::CallType::LOOKUP_SLOT_CALL;
      case Call::NAMED_PROPERTY_CALL:
        return ::Ast::Call::CallType::NAMED_PROPERTY_CALL;
      case Call::KEYED_PROPERTY_CALL:
        return ::Ast::Call::CallType::KEYED_PROPERTY_CALL;
      case Call::NAMED_SUPER_PROPERTY_CALL:
        return ::Ast::Call::CallType::NAMED_SUPER_PROPERTY_CALL;
      case Call::KEYED_SUPER_PROPERTY_CALL:
        return ::Ast::Call::CallType::KEYED_SUPER_PROPERTY_CALL;
      case Call::SUPER_CALL:
        return ::Ast::Call::CallType::SUPER_CALL;
      case Call::OTHER_CALL:
        return ::Ast::Call::CallType::OTHER_CALL;
      default:
        UNREACHABLE();
    }
  }

  virtual void VisitCall(Call* node) {
    auto callnode = current_.AsExpression().getNodeVal().initCall();
    callnode.setCallType(ToCallType(node->GetCallType(isolate_)));
    HandleExpressionList(
        node->arguments(),
        callnode.initArguments(node->arguments()->length()));
    DO_VISIT_EXPRESSION(node, expression, callnode.initExpression());
  }

  virtual void VisitCallNew(CallNew* node) {
    auto callnew = current_.AsExpression().getNodeVal().initCallNew();
    DO_VISIT_EXPRESSION(node, expression, callnew.initExpression());
    HandleExpressionList(node->arguments(),
                         callnew.initArguments(node->arguments()->length()));
  }

  virtual void VisitCallRuntime(CallRuntime* node) {
    auto callruntime = current_.AsExpression().getNodeVal().initCallRuntime();
    HandleExpressionList(
        node->arguments(),
        callruntime.initArguments(node->arguments()->length()));
    auto fn = callruntime.initInfo().getFn();
    if (node->is_jsruntime()) {
      fn.setContextIndex(node->context_index());
    } else {
      auto rf = fn.initRuntimeFunction();
      rf.setId(node->function()->function_id);
      rf.setName(node->function()->name);
    }
  }

  virtual void VisitUnaryOperation(UnaryOperation* node) {
    auto unary = current_.AsExpression().getNodeVal().initUnaryOperation();
    unary.setToken(ToAstToken(node->op()));
    DO_VISIT_EXPRESSION(node, expression, unary.initExpression());
  }

  virtual void VisitBinaryOperation(BinaryOperation* node) {
    auto binary = current_.AsExpression().getNodeVal().initBinaryOperation();
    binary.setToken(ToAstToken(node->op()));
    DO_VISIT_EXPRESSION(node, left, binary.initLeft());
    DO_VISIT_EXPRESSION(node, right, binary.initRight());
  }

  virtual void VisitCompareOperation(CompareOperation* node) {
    auto cmp = current_.AsExpression().getNodeVal().initCompareOperation();
    cmp.setToken(ToAstToken(node->op()));
    DO_VISIT_EXPRESSION(node, left, cmp.initLeft());
    DO_VISIT_EXPRESSION(node, right, cmp.initRight());
    // TODO: set the type on the output correctly
  }

  virtual void VisitEmptyParentheses(EmptyParentheses* node) {
    auto empty = current_.AsExpression().getNodeVal().initEmptyParentheses();
  }

  virtual void VisitThisFunction(ThisFunction* node) {
    auto empty = current_.AsExpression().getNodeVal().initThisFunction();
  }

  virtual void VisitCountOperation(CountOperation* node) {
    auto countop = current_.AsExpression().getNodeVal().initCountOperation();
    countop.setOperation(ToAstToken(node->op()));
    countop.setIsPrefix(node->is_prefix());
    countop.setIsPostfix(node->is_postfix());
    countop.setStoreMode(ToAstKeyedAccessStoreMode(node->GetStoreMode()));
    DO_VISIT_EXPRESSION(node, expression, countop.initExpression());
  }

  virtual void VisitDoExpression(DoExpression* node) {
    auto doexp = current_.AsExpression().getNodeVal().initDoExpression();
    HandleBlockNode(node->block(), doexp.initBlock());
    HandleVariableProxyNode(node->result(), doexp.initResult());
    FunctionLiteral* fnlit = node->represented_function();
    if (fnlit != nullptr) {
      HandleFunctionLiteralNode(
          fnlit, doexp.initRepresentedFunction());
    }
  }

  virtual void VisitYield(Yield* node) {
    auto yield = current_.AsExpression().getNodeVal().initYield();
    DO_VISIT_EXPRESSION(node, generator_object, yield.initGenerator());
    DO_VISIT_EXPRESSION(node, expression, yield.initExpression());
  }

  virtual void VisitRewritableExpression(RewritableExpression* node) {
    Visit(node->expression());
  }

  virtual void VisitSpread(Spread* node) {
    auto spread = current_.AsExpression().getNodeVal().initSpread();
    DO_VISIT_EXPRESSION(node, expression, spread.initExpression());
  }
  virtual void VisitSuperPropertyReference(SuperPropertyReference* node) {
    auto super_prop =
      current_.AsExpression().getNodeVal().initSuperPropertyReference();
    if (node->this_var()) {
      HandleVariableProxyNode(node->this_var(), super_prop.initThisVar());
    }
    if (node->home_object()) {
      DO_VISIT_EXPRESSION(node, home_object, super_prop.initHomeObject());
    }
  }
  virtual void VisitSuperCallReference(SuperCallReference* node) {
    auto super_call =
      current_.AsExpression().getNodeVal().initSuperCallReference();
    if (node->this_var()) {
      HandleVariableProxyNode(node->this_var(), super_call.initThisVar());
    }

    if (node->new_target_var()) {
      HandleVariableProxyNode(
          node->new_target_var(), super_call.initNewTargetVar());
    }

    if (node->this_function_var()) {
      HandleVariableProxyNode(node->this_function_var(),
                              super_call.initThisFunctionVar());
    }
  }
  virtual void VisitClassLiteral(ClassLiteral* node) {
    auto class_lit = current_.AsExpression().getNodeVal().initClassLiteral();
    if (node->class_variable_proxy()) {
      HandleVariableProxyNode(
          node->class_variable_proxy(), class_lit.initClassVariable());
    }

    if (node->extends()) {
      DO_VISIT_EXPRESSION(node, extends, class_lit.initExtends());
    }

    if (node->constructor()) {
      HandleFunctionLiteralNode(
          node->constructor(), class_lit.initConstructor());
    }
  }

  void DoHandleScope(Scope* scope, ::Ast::ScopePointer::Builder builder) {
    ReferenceScope(scope, builder);
  }

  void ReferenceScope(Scope* scope, ::Ast::ScopePointer::Builder builder) {
    builder.setParentExprId(reinterpret_cast<uint64_t>(scope));
  }

  AstNodeBuilder current_;
  Isolate* isolate_;
  ConcolicExecutor& indexer_;
  NodeLabel::Labeler labeler_;
  BuilderSerializer serializer_;
};

bool SerializeAst(ParseInfo* info) {
  FunctionLiteral* ast = info->literal();
  Isolate* isolate = info->isolate();
  Handle<Script> script =  info->script();
  MessageHolder message;
  AstSerializer serializer(
      isolate, TaintTracker::FromIsolate(isolate)->Get()->Exec());
  auto ast_message = message.InitRoot().getMessage().initAst();
  if (FLAG_taint_tracking_enable_export_ast) {
    serializer.Start(ast, ast_message);
  }
  Handle<Object> source = handle(script->source(), isolate);
  if (FLAG_taint_tracking_enable_source_export) {
    message.WriteConcreteObject(
        ast_message.initSource(),
        ObjectSnapshot(source));
  }
  if (FLAG_taint_tracking_enable_source_hash_export) {
    std::stringstream source_hash_stream;
    auto source_hash_builder = ast_message.initSourceHash();
    if (source->IsString()) {
      source_hash_stream << Sha256StringAsHex(Handle<String>::cast(source));
      source_hash_builder.getType().setBuiltin(Ast::Hash::HashKind::SHA256);
    } else {
      source_hash_stream << "__error_not_string_type: ";
      source->ShortPrint(source_hash_stream);
      source_hash_builder.getType().setBuiltin(Ast::Hash::HashKind::UNKNOWN);
    }
    source_hash_builder.setHashValue(source_hash_stream.str());
  }
  message.CopyJsObjectToStringSlow(
      ast_message.initSourceUrl(),
      handle(script->source_url(), isolate));
  message.CopyJsObjectToStringSlow(
      ast_message.initScriptName(),
      handle(script->name(), isolate));

  ast_message.setScriptId(script->id());

  int start_position = ast->start_position();
  int end_position = ast->end_position();
  ast_message.setStartPosition(start_position);
  ast_message.setEndPosition(end_position);
  ast_message.setFunctionTokenPosition(info->function_token_position());

  bool should_log = true;
  if (FLAG_taint_tracking_logging_remove_native_scripts) {
    if (script->type() == Script::TYPE_NATIVE) {
      should_log = false;
    }

    if (script->type() == Script::TYPE_EXTENSION) {
      should_log = false;
    }
  }
  if (should_log) {
    TaintTracker::Impl::LogToFile(isolate, message, FlushConfig::FORCE_FLUSH);
  }
  return true;
}

}
