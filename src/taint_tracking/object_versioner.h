#ifndef OBJECT_VERSIONER_H
#define OBJECT_VERSIONER_H

// Used to store an immutable copy of an object during symbolic execution


#include "src/objects.h"

#include "src/taint_tracking-inl.h"

#include "ast.capnp.h"
#include "logrecord.capnp.h"

#include "symbolic_state.h"
#include <memory>

namespace tainttracking {

class ObjectSnapshot;

class RevisionInfo {
public:
  enum Type {
    APPEND,
    DELETE,
    REPLACE
  };

  static const int HAS_NOT_BEEN_SERIALIZED = -1;

  static const int IDX_REVISION_NUMBER = 0;
  static const int IDX_REVISION_TYPE = IDX_REVISION_NUMBER + 1;
  static const int IDX_REVISION_KEY = IDX_REVISION_TYPE + 1;
  static const int IDX_REVISION_VALUE = IDX_REVISION_KEY + 1;
  static const int IDX_HAS_BEEN_SERIALIZED = IDX_REVISION_VALUE + 1;
  static const int IDX_SIZE = IDX_HAS_BEEN_SERIALIZED + 1;

  RevisionInfo() = delete;
  RevisionInfo(
      v8::internal::Handle<v8::internal::ArrayList> holder, int index);

  int GetRevisionNumber() const;
  Type GetType() const;
  v8::internal::String* GetKey() const;

  // Only valid for replace and delete types, otherwise is the_hole
  v8::internal::Object* GetPrevVal() const;

  bool HasBeenSerialized() const;
  int SerializedUniqueId() const;

  void SetRevisionNumber(int number);
  void SetType(Type type);
  void SetKey(v8::internal::String* obj);
  void SetValue(v8::internal::Object* obj);
  void SetSerializedUniqueId(int obj);

private:
  void SetIndexOffset(v8::internal::Object* obj, int offset);
  void SetIndexOffset(int obj, int offset);

  int GetIndexOffsetSmi(int offset) const;
  v8::internal::Object* GetIndexOffset(int offset) const;

  v8::internal::Handle<v8::internal::ArrayList> holder_;
  int base_index_;
};


class ImmutableRevisionList {
public:

  class Iterator {
  public:
    Iterator(int index);

    Iterator Increment() const;
    Iterator Decrement() const;
    bool operator==(const Iterator& other) const;
    bool operator!=(const Iterator& other) const;
    bool operator<=(const Iterator& other) const;
    bool operator>=(const Iterator& other) const;
    int Difference(const Iterator& other) const;
    Iterator Between(const Iterator& other) const;

    int BaseIndex() const;

  private:
    friend class ImmutableRevisionList;

    int index_;
  };

  static const int REVISION_SIZE_IDX = 0;

  static const int NO_REVISION = -1;

  ImmutableRevisionList(v8::internal::Handle<v8::internal::ArrayList> mem);
  ImmutableRevisionList() = delete;

  Iterator begin() const;
  Iterator end() const;
  RevisionInfo GetRevisionInfo(Iterator pos) const;
  Iterator RevisionAt(int revision_number) const;

  static v8::internal::Handle<v8::internal::ArrayList> NewList(
      v8::internal::Isolate* isolate);
  static v8::internal::Handle<v8::internal::ArrayList> AppendToMemory(
    v8::internal::Handle<v8::internal::ArrayList> mem,
    int revision,
    RevisionInfo::Type type,
    v8::internal::Handle<v8::internal::String> key,
    v8::internal::Handle<v8::internal::Object> val);

private:
  const v8::internal::Handle<v8::internal::ArrayList> mem_;
};



class ObjectVersioner {
public:
  ObjectVersioner() = delete;
  ObjectVersioner(v8::internal::Isolate* isolate);

  void Init();

  void OnSet(
      v8::internal::Handle<v8::internal::JSReceiver> target,
      v8::internal::Handle<v8::internal::String> key,
      v8::internal::Handle<v8::internal::Object> prev_value);

  void OnRemove(
      v8::internal::Handle<v8::internal::JSReceiver> target,
      v8::internal::Handle<v8::internal::String> key,
      v8::internal::Handle<v8::internal::Object> prev_value);

  void OnAppend(
      v8::internal::Handle<v8::internal::JSReceiver> target,
      v8::internal::Handle<v8::internal::String> key);

  ObjectSnapshot TakeSnapshot(
      v8::internal::Handle<v8::internal::Object> target);

  // Must be a HeapObject in ObjectSnapshot
  Status MaybeSerialize(
      ObjectSnapshot snapshot,
      Ast::JsObjectValue::Builder builder,
      MessageHolder& holder);

  static ObjectVersioner& FromIsolate(v8::internal::Isolate* isolate);

private:
  void AppendNewRevision(
      v8::internal::Handle<v8::internal::JSReceiver> target,
      RevisionInfo::Type type,
      v8::internal::Handle<v8::internal::String> key,
      v8::internal::Handle<v8::internal::Object> prev_value);

  void PutInMap(
    v8::internal::Handle<v8::internal::HeapObject> target,
    v8::internal::Handle<v8::internal::HeapObject> value);

  v8::internal::Handle<v8::internal::WeakHashTable> GetTable();

  std::unique_ptr<LiteralValueHolder> weak_object_map_;
  int current_version_;
  int unique_immutable_id_;
  v8::internal::Isolate* isolate_;
};


}

#endif
