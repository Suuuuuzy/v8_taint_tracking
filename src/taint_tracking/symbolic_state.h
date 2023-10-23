#ifndef SYMBOLIC_STATE_H
#define SYMBOLIC_STATE_H


// Class for defining the symbolic value of a javascript object. Used during
// symbolic execution.


#include "src/global-handles.h"
#include "src/taint_tracking.h"

#include "ast.capnp.h"
#include "logrecord.capnp.h"


#include <capnp/message.h>

#include <memory>
#include <set>

namespace tainttracking {

class MessageHolder;
template <typename T> class GarbageCollectableManager;
class SymbolicObjectProperties;
class ObjectPropertySymbolicStateManager;



template <typename KeySym, typename ValSym>
class KeyValueStruct {
public:
  KeyValueStruct(KeySym key, ValSym value) : key_(key), value_(value) {}

  KeyValueStruct(const KeyValueStruct<KeySym, ValSym>& other) :
    key_(other.key_), value_(other.value_) {}

  ~KeyValueStruct() {}

  KeyValueStruct<KeySym, ValSym>& operator=(
      const KeyValueStruct<KeySym, ValSym>& other) {
    key_ = other.key_;
    value_ = other.value_;
    return *this;
  }

  KeySym GetKey() const {
    return key_;
  }

  ValSym GetValue() const {
    return value_;
  }

private:
  KeySym key_;
  ValSym value_;
};


class LiteralValueHolder {
public:

  LiteralValueHolder(v8::internal::Handle<v8::internal::Object> value,
                     v8::internal::Isolate* isolate);
  LiteralValueHolder(const LiteralValueHolder&) = delete;

  LiteralValueHolder& operator=(const LiteralValueHolder&) = delete;

  LiteralValueHolder() = delete;

  virtual ~LiteralValueHolder();

  v8::internal::Handle<v8::internal::Object> Get();

protected:
  v8::internal::Handle<v8::internal::Object> global_handle_;
};

template <typename T>
class WeakLiteralValueHolder : public LiteralValueHolder {
private:

  class OnDestroy {
  public:
    virtual void NotifyObjectDestroyed(WeakLiteralValueHolder<T>*) = 0;
  };

  friend class GarbageCollectableManager<T>;

  WeakLiteralValueHolder(
      v8::internal::Handle<v8::internal::Object> value,
      v8::internal::Isolate* isolate,
      std::unique_ptr<T> linked,
      OnDestroy* listener) :
    LiteralValueHolder(value, isolate),
    linked_lifetime_(std::move(linked)),
    on_destroy_listener_(listener) {
    v8::internal::GlobalHandles::MakeWeak(
        global_handle_.location(),
        reinterpret_cast<void*>(this),
        CallDestructionCallback,
        v8::WeakCallbackType::kParameter);
  }

  virtual ~WeakLiteralValueHolder() {}

  void ForceDestroy() {
    WeakLiteralValueHolder* this_obj = reinterpret_cast<WeakLiteralValueHolder*>(
        v8::internal::GlobalHandles::ClearWeakness(global_handle_.location()));
    DCHECK_EQ(this, this_obj);
    delete this;
  }

  T* LinkedObject() {
    return linked_lifetime_.get();
  }

  static void CallDestructionCallback(
      const v8::WeakCallbackInfo<void>& dispose) {
    WeakLiteralValueHolder* info =
      reinterpret_cast<WeakLiteralValueHolder*>(dispose.GetParameter());
    info->on_destroy_listener_->NotifyObjectDestroyed(info);
    info->ForceDestroy();
  }

  std::unique_ptr<T> linked_lifetime_;
  OnDestroy* on_destroy_listener_;
};


template <typename T>
class GarbageCollectableManager : public WeakLiteralValueHolder<T>::OnDestroy {
public:
  class Listener {
  public:
    Listener() {}
    virtual ~Listener() {}
    virtual void OnBeforeDestroy(T* item) = 0;
  };

  GarbageCollectableManager(v8::internal::Isolate* isolate) :
    listener_(nullptr), isolate_(isolate) {}

  ~GarbageCollectableManager() {
    for (auto ptr : outstanding_) {
      if (listener_) {
        listener_->OnBeforeDestroy(ptr->linked_lifetime_.get());
      }
      ptr->ForceDestroy();

      #ifdef DEBUG
      allocated_ -= 1;
      #endif
    }
    outstanding_.clear();
    DCHECK_EQ(0, outstanding_.size());
    DCHECK_EQ(0, allocated_);
  }

  virtual void NotifyObjectDestroyed(WeakLiteralValueHolder<T>* obj) {
    #ifdef DEBUG
    allocated_ -= 1;
    #endif

    auto iterator = outstanding_.find(obj);
    DCHECK(iterator != outstanding_.end());
    if (listener_) {
      listener_->OnBeforeDestroy((*iterator)->LinkedObject());
    }
    outstanding_.erase(iterator);
  }

  void New(v8::internal::Handle<v8::internal::Object> value,
           std::unique_ptr<T> linked) {
    #ifdef DEBUG
    allocated_ += 1;
    #endif

    outstanding_.insert(
        new WeakLiteralValueHolder<T>(
            value, isolate_, std::move(linked), this));
  }

  void AddListener(Listener* listener) {
    listener_ = listener;
  }

private:
  #ifdef DEBUG
  uint64_t allocated_ = 0;
  #endif

  Listener* listener_;
  v8::internal::Isolate* isolate_;
  std::set<WeakLiteralValueHolder<T>*> outstanding_;
};


class SymbolicMessageWriter {
public:
  SymbolicMessageWriter() {}
  virtual ~SymbolicMessageWriter() {}
  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) = 0;
};



class SymbolicState {
public:

  void WriteSelf(::TaintLogRecord::SymbolicValue::Builder builder,
                 MessageHolder& holder);

  void AddComment(const std::string& comment);

  enum MergeType {
    CALL,
    PROPERTY,
  };

  static std::shared_ptr<SymbolicState> MergeWith(
      std::shared_ptr<SymbolicState> primary,
      std::shared_ptr<SymbolicState> other,
      MergeType merge_type,
      v8::internal::Isolate* isolate);

  bool DebugCheckObjectEquals(
      v8::internal::Handle<v8::internal::Object> other);

  void DebugPrintObject();

  // Mutable objects (e.g., JSObject or JSArray) may have properties that change
  // between the time the symbolic state is made and the time that it is
  // serialized. In order to serialize the value of the object at the previous
  // point in time when the symbolic state was made, we can force the
  // serialization of the object early so that we take a snapshot of the state.
  // This is a costly operation, so we only want to force this when:
  //
  // 1) We access a property with a symbolic key
  // 2) We assign a property with a symbolic key or symbolic value
  void ForceSerialization();

private:
  void WriteSelfImpl(::TaintLogRecord::SymbolicValue::Builder builder,
                     MessageHolder& holder);

  void WriteSelfForceSerialize(
      ::TaintLogRecord::SymbolicValue::Builder builder,
      MessageHolder& holder);

  friend class SymbolicFactory;

  SymbolicState(v8::internal::Handle<v8::internal::Object> val,
                v8::internal::Isolate* isolate,
                const NodeLabel& label,
                std::unique_ptr<SymbolicMessageWriter> writer,
                int64_t unique_id);

  SymbolicState() = delete;

  std::unique_ptr<SymbolicMessageWriter> writer_;
  std::vector<std::string> comments_;
  LiteralValueHolder holder_;
  NodeLabel label_;
  int64_t unique_id_;
  bool already_serialized_;
  std::unique_ptr<MessageHolder> previous_forced_serialized_;
  v8::internal::Isolate* isolate_;
};



typedef KeyValueStruct<std::shared_ptr<SymbolicState>,
                       std::shared_ptr<SymbolicState>> SymbolicKeyValue;


class SymbolicObjectProperties : public SymbolicMessageWriter {
public:
  SymbolicObjectProperties() {}
  virtual ~SymbolicObjectProperties() {}
  virtual void ToMessage(::TaintLogRecord::SymbolicValue::Builder builder,
                         MessageHolder& holder) = 0;
};



class SymbolicFactory {
public:
  SymbolicFactory(v8::internal::Isolate* isolate,
                  v8::internal::Handle<v8::internal::Object> concrete,
                  const NodeLabel& label);

  SymbolicFactory(v8::internal::Isolate* isolate,
                  v8::internal::Handle<v8::internal::Object> concrete);

  SymbolicFactory(v8::internal::Isolate* isolate);

  std::shared_ptr<SymbolicState> MakeSymbolic() const;

  std::shared_ptr<SymbolicState> FromLiteral() const;

  std::shared_ptr<SymbolicState> IfThenElse(
      std::shared_ptr<SymbolicState> cond_exp,
      std::shared_ptr<SymbolicState> then_exp,
      std::shared_ptr<SymbolicState> else_exp) const;

  std::shared_ptr<SymbolicState> Undefined() const;
  std::shared_ptr<SymbolicState> OptimizedOut() const;
  std::shared_ptr<SymbolicState> LValue() const;
  std::shared_ptr<SymbolicState> Unexecuted() const;

  enum UninstrumentedType {
    RECEIVER,
    THROWN_EXCEPTION,
    ARGUMENT,
    OPTIMIZED_OUT,
  };
  std::shared_ptr<SymbolicState> Uninstrumented(UninstrumentedType) const;

  // Message root is a Ast::JsObjectValue
  std::shared_ptr<SymbolicState> FromAstLiteral(
      std::shared_ptr<::capnp::MallocMessageBuilder> ast_literal) const;

  std::shared_ptr<SymbolicState> Call(
      std::shared_ptr<SymbolicState> exp,
      std::vector<std::shared_ptr<SymbolicState>> args) const;

  std::shared_ptr<SymbolicState> CallNew(
      std::shared_ptr<SymbolicState> exp,
      std::vector<std::shared_ptr<SymbolicState>> args) const;

  std::shared_ptr<SymbolicState> CallRuntime(
      std::string name,
      std::vector<std::shared_ptr<SymbolicState>> args) const;

  std::shared_ptr<SymbolicState> CallRuntime(
      int32_t context_index,
      std::vector<std::shared_ptr<SymbolicState>> args) const;

  std::shared_ptr<SymbolicState> Operation(
      ::Ast::Token op,
      std::shared_ptr<SymbolicState> arg) const;

  std::shared_ptr<SymbolicState> Operation(
      ::Ast::Token op,
      std::shared_ptr<SymbolicState> arga,
      std::shared_ptr<SymbolicState> argb) const;

  std::shared_ptr<SymbolicState> GetProperty(
      std::shared_ptr<SymbolicState> obj,
      std::shared_ptr<SymbolicState> key) const;

  std::shared_ptr<SymbolicState> ApiDocumentUrl() const;

  std::shared_ptr<SymbolicState> ArrayLiteral(
      std::vector<std::shared_ptr<SymbolicState>> values) const;

  std::shared_ptr<SymbolicState> ObjectLiteral(
      std::vector<SymbolicKeyValue> key_values) const;

  std::shared_ptr<SymbolicState> ObjectWithSymbolicProperties(
      std::shared_ptr<SymbolicState> prev_state,
      const SymbolicKeyValue& key_value) const;


  // Should only be used for debugging purposes
  bool DebugCheckObjectEquals(
      std::shared_ptr<SymbolicState> state) const;

  void SetConcrete(v8::internal::Handle<v8::internal::Object> new_concrete);

private:
  SymbolicFactory();

  std::shared_ptr<SymbolicState> Make(
      SymbolicMessageWriter* writer) const;

  v8::internal::Isolate* isolate_;
  v8::internal::Handle<v8::internal::Object> concrete_;
  NodeLabel label_;
};


}


#endif
