#include "symbolic_state.h"

#include "src/taint_tracking-inl.h"

#include "src/builtins/builtins.h"

using namespace v8::internal;

namespace tainttracking {



LiteralValueHolder::LiteralValueHolder(
    Handle<Object> value, Isolate* isolate) {
  DCHECK_NOT_NULL(isolate);
  global_handle_ = isolate->global_handles()->Create(*value.location());
}

LiteralValueHolder::~LiteralValueHolder() {
  GlobalHandles::Destroy(global_handle_.location());
}

Handle<Object> LiteralValueHolder::Get() {
  return global_handle_;
}



class SymbolicMergedState : public SymbolicMessageWriter {
public:
  SymbolicMergedState(SymbolicState::MergeType type,
                      std::shared_ptr<SymbolicState> primary,
                      std::shared_ptr<SymbolicState> secondary) :
    type_(type), primary_(primary), secondary_(secondary) {}

  virtual ~SymbolicMergedState() {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto merged = builder.getValue().initMerged();
    switch (type_) {
      case SymbolicState::MergeType::CALL:
        merged.setType(TaintLogRecord::SymbolicValue::MergedState::Type::CALL);
        break;

      case SymbolicState::MergeType::PROPERTY:
        merged.setType(
            TaintLogRecord::SymbolicValue::MergedState::Type::PROPERTY);
        break;
    }
    primary_->WriteSelf(merged.initPrimary(), holder);
    secondary_->WriteSelf(merged.initSecondary(), holder);
  }

private:
  SymbolicState::MergeType type_;
  std::shared_ptr<SymbolicState> primary_;
  std::shared_ptr<SymbolicState> secondary_;
};


SymbolicState::SymbolicState(
    v8::internal::Handle<v8::internal::Object> val,
    v8::internal::Isolate* isolate,
    const NodeLabel& label,
    std::unique_ptr<SymbolicMessageWriter> writer,
    int64_t unique_id) :
  writer_(std::move(writer)),
  comments_(),
  holder_(val, isolate),
  label_(label),
  unique_id_(unique_id),
  already_serialized_(false),
  previous_forced_serialized_(nullptr),
  isolate_(isolate) {}


std::shared_ptr<SymbolicState> SymbolicState::MergeWith(
    std::shared_ptr<SymbolicState> primary,
    std::shared_ptr<SymbolicState> other,
    MergeType merged_type,
    v8::internal::Isolate* isolate) {
  if (primary->unique_id_ == other->unique_id_) {
    return primary;
  }

  DCHECK(primary->DebugCheckObjectEquals(other->holder_.Get()));
  return std::shared_ptr<SymbolicState>(
      new SymbolicState(
          primary->holder_.Get(),
          isolate,
          NodeLabel(),
          std::unique_ptr<SymbolicMessageWriter>(
              new SymbolicMergedState(merged_type, primary, other)),
          TaintTracker::FromIsolate(isolate)->Get()->NewInstance()));
}


bool SymbolicState::DebugCheckObjectEquals(
    v8::internal::Handle<v8::internal::Object> other) {
  return true;

  // TODO: These checks fail because, now we are storing copies of mutable
  // objects instead of the objects themselves. This is expected to fail the
  // is_identical_to check. However, would be good to change this check to still
  // check for equality for immutable objects.
  //
  // return holder_.Get().is_identical_to(other);
}


void SymbolicState::ForceSerialization() {
  return;
}


class SymbolicBinaryOperation : public SymbolicMessageWriter {
public:
  SymbolicBinaryOperation(
      ::Ast::Token operation,
      std::shared_ptr<SymbolicState> left,
      std::shared_ptr<SymbolicState> right) :
    operation_(operation),
    left_(left),
    right_(right) {}

  virtual ~SymbolicBinaryOperation() {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto op = builder.getValue().initBinaryOperation();
    op.setToken(operation_);
    left_->WriteSelf(op.initLeft(), holder);
    right_->WriteSelf(op.initRight(), holder);
  }

private:
  ::Ast::Token operation_;
  std::shared_ptr<SymbolicState> left_;
  std::shared_ptr<SymbolicState> right_;
};

class SymbolicUnaryOperation : public SymbolicMessageWriter {
public:
  SymbolicUnaryOperation(
      ::Ast::Token operation,
      std::shared_ptr<SymbolicState> expression) :
    operation_(operation),
    expression_(expression) {}

  virtual ~SymbolicUnaryOperation() {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto op = builder.getValue().initUnaryOperation();
    op.setToken(operation_);
    expression_->WriteSelf(op.initExpression(), holder);
  }

private:
  ::Ast::Token operation_;
  std::shared_ptr<SymbolicState> expression_;
};

class SymbolicConditional : public SymbolicMessageWriter {
public:
  SymbolicConditional(
      std::shared_ptr<SymbolicState> cond_exp,
      std::shared_ptr<SymbolicState> then_exp,
      std::shared_ptr<SymbolicState> else_exp) :
    cond_exp_(cond_exp),
    then_exp_(then_exp),
    else_exp_(else_exp) {}
  virtual ~SymbolicConditional() {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto cond_exp = builder.getValue().initConditional();
    cond_exp_->WriteSelf(cond_exp.initCond(), holder);
    then_exp_->WriteSelf(cond_exp.initThen(), holder);
    else_exp_->WriteSelf(cond_exp.initElse(), holder);
  }

private:
  std::shared_ptr<SymbolicState> cond_exp_;
  std::shared_ptr<SymbolicState> then_exp_;
  std::shared_ptr<SymbolicState> else_exp_;
};


class SymbolicPropertyAccess : public SymbolicMessageWriter {
public:
  SymbolicPropertyAccess(
      std::shared_ptr<SymbolicState> obj,
      std::shared_ptr<SymbolicState> key) :
    obj_(obj),
    key_(key) {}

  virtual ~SymbolicPropertyAccess() {}

  void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                MessageHolder& holder) override {
    auto prop_builder = builder.getValue().initProperty();
    obj_->WriteSelf(prop_builder.initObj(), holder);
    key_->WriteSelf(prop_builder.initKey(), holder);
  }

private:
  std::shared_ptr<SymbolicState> obj_;
  std::shared_ptr<SymbolicState> key_;
};


void SymbolicState::AddComment(const std::string& comment) {
  comments_.push_back(comment);
}

void SymbolicState::WriteSelf(
    ::TaintLogRecord::SymbolicValue::Builder builder,
    MessageHolder& message_holder) {
  if (already_serialized_) {
    builder.setUniqueId(unique_id_);
    builder.getValue().setAlreadySerialized();
  } else {
    if (previous_forced_serialized_) {
      TaintTracker::Impl::LogToFile(isolate_, *previous_forced_serialized_);
      builder.setUniqueId(unique_id_);
      builder.getValue().setAlreadySerialized();
      previous_forced_serialized_.reset();
    } else {
      WriteSelfImpl(builder, message_holder);
    }

    already_serialized_ = true;
  }
}

void SymbolicState::WriteSelfForceSerialize(
    ::TaintLogRecord::SymbolicValue::Builder builder,
    MessageHolder& holder) {
  WriteSelfImpl(builder, holder);
}

void SymbolicState::WriteSelfImpl(
    ::TaintLogRecord::SymbolicValue::Builder builder,
    MessageHolder& message_holder) {
  builder.setUniqueId(unique_id_);

  BuilderSerializer ser;
  if (label_.IsValid()) {
    ser.Serialize(builder.initLabel(), label_);
  }
  writer_->ToMessage(builder, message_holder);


  Handle<Object> value = holder_.Get();
  if (!message_holder.WriteConcreteObject(builder.initConcrete(), value)) {
    std::stringstream comment;
    value->Print(comment);
    AddComment(comment.str());
    std::stringstream typeinfo;

    // Because SMI's will not fail
    DCHECK(value->IsHeapObject());

    typeinfo << Handle<HeapObject>::cast(value)->map()->instance_type();
    AddComment(typeinfo.str());
  }
  auto comment_builder = builder.initComment(comments_.size());
  for (int i = 0; i < comments_.size(); ++i) {
    comment_builder.set(i, comments_[i]);
  }
}


class SymbolicLiteralValue : public SymbolicMessageWriter {
public:
  virtual void ToMessage(
      ::TaintLogRecord::SymbolicValue::Builder builder,
      MessageHolder& holder) {
    builder.getValue().setLiteral();
  }
};



class SymbolicDummy : public SymbolicMessageWriter {
public:
  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    builder.getValue().setDummy();
  }
};

class SymbolicOptimizedOut : public SymbolicMessageWriter {
public:
  SymbolicOptimizedOut(SymbolicFactory::UninstrumentedType type) :
    type_(type) {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    builder.getValue().initOptimizedOut().setType(FromType());
  }

private:
  TaintLogRecord::SymbolicValue::Uninstrumented::Type FromType() {
    switch (type_) {
      case SymbolicFactory::UninstrumentedType::RECEIVER:
        return TaintLogRecord::SymbolicValue::Uninstrumented::Type::RECEIVER;

      case SymbolicFactory::UninstrumentedType::THROWN_EXCEPTION:
        return TaintLogRecord::SymbolicValue::Uninstrumented::Type::THROWN_EXCEPTION;

      case SymbolicFactory::UninstrumentedType::ARGUMENT:
        return TaintLogRecord::SymbolicValue::Uninstrumented::Type::ARGUMENT;

      case SymbolicFactory::UninstrumentedType::OPTIMIZED_OUT:
        return TaintLogRecord::SymbolicValue::Uninstrumented::Type::OPTIMIZED_OUT;

      default:
        return TaintLogRecord::SymbolicValue::Uninstrumented::Type::UNKNOWN;
    }
  }

  SymbolicFactory::UninstrumentedType type_;
};

class SymbolicUnconstraintedString : public SymbolicMessageWriter {
public:
  SymbolicUnconstraintedString(Handle<String> string) :
    taint_info_(InitTaintRanges(string)) {}

  virtual ~SymbolicUnconstraintedString() {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto taint = builder.getValue().initTaintedInput();
    auto info = taint.initTaintValue();
    InitTaintInfo(taint_info_, &info);
  }

private:
  std::vector<std::tuple<TaintType, int>> taint_info_;
};


class SymbolicAstLiteral : public SymbolicMessageWriter {
public:
  SymbolicAstLiteral(
      std::shared_ptr<::capnp::MallocMessageBuilder> lit) :
    literal_(lit) {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto value = builder.getValue();
    value.setAstLiteral(
        literal_->getRoot<::Ast::JsObjectValue>().asReader());
    value.getAstLiteral().setUniqueId(MessageHolder::NO_UNIQUE_ID);
    builder.setUniqueId(MessageHolder::NO_UNIQUE_ID);
  }

private:
  std::shared_ptr<::capnp::MallocMessageBuilder> literal_;
};


class SymbolicCall : public SymbolicMessageWriter {
public:
  enum Type {
    CALL_NEW,
    CALL
  };

  SymbolicCall(std::shared_ptr<SymbolicState> exp,
               std::vector<std::shared_ptr<SymbolicState>> args,
               Type type) :
    exp_(exp), args_(std::move(args)), type_(type) {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto call_builder = builder.getValue().initCall();
    call_builder.setType(GetType());
    exp_->WriteSelf(call_builder.initExpression(), holder);
    auto arg_builder = call_builder.initArgs(args_.size());
    for (int i = 0; i < args_.size(); i++) {
      args_[i]->WriteSelf(arg_builder[i], holder);
    }
  }

private:
  TaintLogRecord::SymbolicValue::Call::Type GetType() {
    switch (type_) {
      case CALL:
        return TaintLogRecord::SymbolicValue::Call::Type::CALL;

      case CALL_NEW:
        return TaintLogRecord::SymbolicValue::Call::Type::CALL_NEW;
    }
  }

  std::shared_ptr<SymbolicState> exp_;
  std::vector<std::shared_ptr<SymbolicState>> args_;
  Type type_;
};



class SymbolicUndefined : public SymbolicMessageWriter {
public:
  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    builder.getValue().setLiteral();
  }
};


SymbolicFactory::SymbolicFactory(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> concrete,
    const NodeLabel& label) :
  isolate_(isolate),
  concrete_(concrete),
  label_(label) {
  DCHECK_NOT_NULL(isolate);
}

SymbolicFactory::SymbolicFactory(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> concrete)
  : SymbolicFactory(isolate, concrete, NodeLabel()) {}

SymbolicFactory::SymbolicFactory(v8::internal::Isolate* isolate) :
  SymbolicFactory(
      isolate, handle(isolate->heap()->undefined_value(), isolate)) {}


class RecursiveObjectSnapshotter : public ObjectOwnPropertiesVisitor {
public:
  static const int INITIAL_SIZE = 16;
  static const int MAX_DEPTH = 1;

  RecursiveObjectSnapshotter() : depth_(0) {}
  RecursiveObjectSnapshotter(int d) : depth_(d) {}

  static bool CanBeDeepCopied(Handle<Object> obj) {
    if (obj->IsHeapObject()) {
      switch (Handle<HeapObject>::cast(obj)->map()->instance_type()) {
        case JS_REGEXP_TYPE:
        case JS_OBJECT_TYPE:
        case JS_ERROR_TYPE:
        case JS_ARRAY_TYPE:
        case JS_API_OBJECT_TYPE:
        case JS_SPECIAL_API_OBJECT_TYPE:
          return true;

        default:
          return false;
      }
    } else {
      return false;
    }
  }

  bool VisitKeyValue(Handle<String> key, Handle<Object> concrete) override {
    if (concrete->IsJSReceiver()) {
      if (CanBeDeepCopied(concrete)) {
        DCHECK(concrete->IsJSObject());
        Handle<JSObject> as_js_obj = Handle<JSObject>::cast(concrete);
        Isolate* isolate = as_js_obj->GetIsolate();
        Object* is_recursive_loop = recursion_guard_->Lookup(as_js_obj);

        Handle<JSObject> value;
        if (is_recursive_loop->IsTheHole(isolate)) {
          Handle<Object> ret_val =
            RecursiveObjectSnapshotter(depth_ + 1).Run(
                as_js_obj, recursion_guard_);
          // TODO: it is possible that this cast will fail because of a stack
          // overflow, or because arbitrary javascript signaled an exception.
          // For now we check and error out if that happens. In the future we
          // should either gracefully handle such errors or make sure they don't
          // happen.
          CHECK (ret_val->IsJSObject());

          value = Handle<JSObject>::cast(ret_val);
        } else {
          DCHECK(is_recursive_loop->IsJSObject());
          value = handle(JSObject::cast(is_recursive_loop), isolate);
        }

        // TODO: The ObjectOwnPropertiesVisitor should only pass DATA elements
        // here.
        auto maybe_obj = Object::SetPropertyOrElement(
            clone_, key, value, SLOPPY);

        // TODO: it is possible to execute arbitrary javascript inside an
        // accessor here, which could change the program's behavior. It would
        // be good to not do that.
        Handle<Object> set_value;
        DCHECK(maybe_obj.ToHandle(&set_value));
      }
      return false;
    } else {
      return false;
    }
  }

  Handle<Object> Run(Handle<JSObject> obj) {
    return Run(obj, WeakHashTable::New(obj->GetIsolate(), INITIAL_SIZE));
  }

private:
  Handle<Object> Run(
      Handle<JSObject> obj,
      v8::internal::Handle<WeakHashTable> recursion_guard) {

    Isolate* isolate = obj->GetIsolate();

    StackLimitCheck check (isolate);
    CHECK (!check.HasOverflowed());

    clone_ = isolate->factory()->CopyJSObject(obj);
    if (depth_ >= MAX_DEPTH) {
      return clone_;
    }

    recursion_guard_ = WeakHashTable::Put(
        recursion_guard, obj, clone_);
    if (!Visit(clone_)) {
      return handle(isolate->heap()->the_hole_value(), isolate);
    }
    return clone_;
  }

  int depth_;
  v8::internal::Handle<WeakHashTable> recursion_guard_;
  Handle<JSObject> clone_;
};


Handle<Object> CopyObject(Handle<Object> obj) {
  if (RecursiveObjectSnapshotter::CanBeDeepCopied(obj)) {
    DCHECK(obj->IsJSObject());
    Handle<JSObject> as_js_obj = Handle<JSObject>::cast(obj);
    return as_js_obj->GetIsolate()->factory()->CopyJSObject(as_js_obj);
  } else {
    return obj;
  }
}


std::shared_ptr<SymbolicState> SymbolicFactory::Make(
    SymbolicMessageWriter* writer) const {
  int64_t new_ctr = TaintTracker::FromIsolate(isolate_)->Get()->NewInstance();

  return std::shared_ptr<SymbolicState> (
      new SymbolicState(CopyObject(concrete_),
                        isolate_,
                        label_,
                        std::unique_ptr<SymbolicMessageWriter>(writer),
                        new_ctr));
}


std::shared_ptr<SymbolicState> SymbolicFactory::Undefined() const {
  return Make(new SymbolicUndefined());
}

std::shared_ptr<SymbolicState> SymbolicFactory::MakeSymbolic() const {
  SymbolicMessageWriter* writer;
  if (concrete_->IsString()) {
    writer = new SymbolicUnconstraintedString(Handle<String>::cast(concrete_));
  } else {
    writer = new SymbolicDummy();
  }
  return Make(writer);
}



std::shared_ptr<SymbolicState> SymbolicFactory::FromLiteral() const {
  return Make(new SymbolicLiteralValue());
}

std::shared_ptr<SymbolicState> SymbolicFactory::IfThenElse(
    std::shared_ptr<SymbolicState> cond_exp,
    std::shared_ptr<SymbolicState> then_exp,
    std::shared_ptr<SymbolicState> else_exp) const {
  return Make(new SymbolicConditional(cond_exp, then_exp, else_exp));
}

std::shared_ptr<SymbolicState> SymbolicFactory::OptimizedOut() const {
  return Uninstrumented(OPTIMIZED_OUT);
}

std::shared_ptr<SymbolicState> SymbolicFactory::Uninstrumented(
    UninstrumentedType type) const {
  return Make(new SymbolicOptimizedOut(type));
}

std::shared_ptr<SymbolicState> SymbolicFactory::Call(
    std::shared_ptr<SymbolicState> exp,
    std::vector<std::shared_ptr<SymbolicState>> args) const {
  return Make(new SymbolicCall(exp, std::move(args), SymbolicCall::CALL));
}


std::shared_ptr<SymbolicState> SymbolicFactory::CallNew(
    std::shared_ptr<SymbolicState> exp,
    std::vector<std::shared_ptr<SymbolicState>> args) const {
  return Make(new SymbolicCall(exp, std::move(args), SymbolicCall::CALL_NEW));
}




std::shared_ptr<SymbolicState> SymbolicFactory::Operation(
    ::Ast::Token operation,
    std::shared_ptr<SymbolicState> arg) const {
  return Make(new SymbolicUnaryOperation(operation, arg));
}

std::shared_ptr<SymbolicState> SymbolicFactory::Operation(
    ::Ast::Token operation,
    std::shared_ptr<SymbolicState> arga,
    std::shared_ptr<SymbolicState> argb) const {
  return Make(new SymbolicBinaryOperation(operation, arga, argb));
}

std::shared_ptr<SymbolicState> SymbolicFactory::FromAstLiteral(
    std::shared_ptr<::capnp::MallocMessageBuilder> ast_literal) const {
  return Make(new SymbolicAstLiteral(ast_literal));
}

class SymbolicUnexecuted : public SymbolicMessageWriter {
public:
  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    builder.getValue().setUnexecuted();
  }
};

std::shared_ptr<SymbolicState> SymbolicFactory::Unexecuted() const {
  return Make(new SymbolicUnexecuted());
}

class SymbolicCallRuntime : public SymbolicMessageWriter {
public:
  SymbolicCallRuntime(std::vector<std::shared_ptr<SymbolicState>> args) :
    args_(args) {}

  virtual ~SymbolicCallRuntime() {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto call = builder.getValue().initCallRuntime();
    Write(call.initExpression());
    auto arg_builder = call.initArgs(args_.size());
    for (int i = 0; i < args_.size(); i++) {
      args_[i]->WriteSelf(arg_builder[i], holder);
    }
  }

  virtual void Write(::Ast::CallRuntime::RuntimeInfo::Builder builder) = 0;

private:
  std::vector<std::shared_ptr<SymbolicState>> args_;
};

class SymbolicCallRuntimeWithContextIndex : public SymbolicCallRuntime {
public:
  SymbolicCallRuntimeWithContextIndex(
      std::vector<std::shared_ptr<SymbolicState>> args,
      int32_t context_index) :
    SymbolicCallRuntime(std::move(args)),
    context_index_(context_index) {}

  virtual ~SymbolicCallRuntimeWithContextIndex() {}

  virtual void Write(::Ast::CallRuntime::RuntimeInfo::Builder builder) {
    builder.getFn().setContextIndex(context_index_);
  }

private:
  uint32_t context_index_;
};

class SymbolicCallRuntimeWithFunctionName : public SymbolicCallRuntime {
public:
  SymbolicCallRuntimeWithFunctionName(
      std::vector<std::shared_ptr<SymbolicState>> args,
      std::string name) :
    SymbolicCallRuntime(std::move(args)),
    name_(name) {}

  virtual ~SymbolicCallRuntimeWithFunctionName() {}

  virtual void Write(::Ast::CallRuntime::RuntimeInfo::Builder builder) {
    auto info = builder.getFn().initRuntimeFunction();
    info.setName(name_);
  }

private:
  std::string name_;
};

std::shared_ptr<SymbolicState> SymbolicFactory::CallRuntime(
    std::string name,
    std::vector<std::shared_ptr<SymbolicState>> args) const {
  return Make(new  SymbolicCallRuntimeWithFunctionName(
                  std::move(args), name));
}

std::shared_ptr<SymbolicState> SymbolicFactory::CallRuntime(
    int32_t context_index,
    std::vector<std::shared_ptr<SymbolicState>> args) const {
  return Make(new  SymbolicCallRuntimeWithContextIndex(
                  std::move(args), context_index));
}

std::shared_ptr<SymbolicState> SymbolicFactory::GetProperty(
    std::shared_ptr<SymbolicState> obj,
    std::shared_ptr<SymbolicState> key) const {
  return Make(new SymbolicPropertyAccess(obj, key));
}

class SymbolicApiDocumentUrl : public SymbolicMessageWriter {
public:
  SymbolicApiDocumentUrl() {}
  virtual ~SymbolicApiDocumentUrl() {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    builder.getValue().initApiValue().getValue().setDocumentUrl();
  }
};

std::shared_ptr<SymbolicState> SymbolicFactory::ApiDocumentUrl() const {
  return Make(new SymbolicApiDocumentUrl());
}


class SymbolicArrayLiteral : public SymbolicMessageWriter {
public:
  SymbolicArrayLiteral(std::vector<std::shared_ptr<SymbolicState>> values) :
    values_(std::move(values)) {}
  virtual ~SymbolicArrayLiteral() {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto literal_builder = builder.getValue().initArrayLiteral().initValues(
        values_.size());
    for (int i = 0; i < values_.size(); i++) {
      values_[i]->WriteSelf(literal_builder[i], holder);
    }
  }

private:
  std::vector<std::shared_ptr<SymbolicState>> values_;
};

class SymbolicObjectLiteral : public SymbolicMessageWriter {
public:
  SymbolicObjectLiteral(std::vector<SymbolicKeyValue> key_values) :
    key_values_(std::move(key_values)) {}

  virtual ~SymbolicObjectLiteral() {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto obj_builder = builder.getValue().initObjectLiteral().initKeyValues(
        key_values_.size());
    for (int i = 0; i < key_values_.size(); i++) {
      key_values_[i].GetKey()->WriteSelf(obj_builder[i].initKey(), holder);
      key_values_[i].GetValue()->WriteSelf(obj_builder[i].initValue(), holder);
    }
  }

private:
  std::vector<SymbolicKeyValue> key_values_;
};


std::shared_ptr<SymbolicState> SymbolicFactory::ArrayLiteral(
    std::vector<std::shared_ptr<SymbolicState>> values) const {
  return Make(new SymbolicArrayLiteral(std::move(values)));
}

std::shared_ptr<SymbolicState> SymbolicFactory::ObjectLiteral(
    std::vector<SymbolicKeyValue> key_values) const {
  return Make(new SymbolicObjectLiteral(std::move(key_values)));
}

bool SymbolicFactory::DebugCheckObjectEquals(
      std::shared_ptr<SymbolicState> state) const {
  return state->DebugCheckObjectEquals(concrete_);
}

void SymbolicState::DebugPrintObject() {
  holder_.Get()->ShortPrint(std::cerr);
}


class SymbolicObjectPropertiesCons : public SymbolicObjectProperties {
public:
  SymbolicObjectPropertiesCons(
      std::shared_ptr<SymbolicState> prev_state,
      const SymbolicKeyValue& keyval) :
    prev_state_(prev_state),
    key_value_(keyval) {}

  virtual ~SymbolicObjectPropertiesCons() {}

  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    auto assignment = builder.getValue().initObjectAssignment();
    auto key_value = assignment.initKeyValue();
    key_value_.GetKey()->WriteSelf(key_value.initKey(), holder);
    key_value_.GetValue()->WriteSelf(key_value.initValue(), holder);
    prev_state_->WriteSelf(assignment.initRest(), holder);
  };

private:
  std::shared_ptr<SymbolicState> prev_state_;
  SymbolicKeyValue key_value_;
};


std::shared_ptr<SymbolicState> SymbolicFactory::ObjectWithSymbolicProperties(
    std::shared_ptr<SymbolicState> prev_state,
    const SymbolicKeyValue& key_value) const {
  return Make(new SymbolicObjectPropertiesCons(prev_state, key_value));
}

void SymbolicFactory::SetConcrete(
    v8::internal::Handle<v8::internal::Object> new_concrete) {
  concrete_ = new_concrete;
}

class SymbolicLValue : public SymbolicMessageWriter {
public:
  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) {
    builder.getValue().setLvalue();
  }
};

std::shared_ptr<SymbolicState> SymbolicFactory::LValue() const {
  return Make(new SymbolicLValue());
}





}
