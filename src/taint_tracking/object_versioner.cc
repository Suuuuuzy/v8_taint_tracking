#include "object_versioner.h"

using namespace v8::internal;

namespace tainttracking {

ObjectSnapshot::ObjectSnapshot(v8::internal::Handle<v8::internal::Object> obj)
  : current_revision_(NO_SNAPSHOT), obj_(obj) {}

ObjectSnapshot::ObjectSnapshot(
    int revision, v8::internal::Handle<v8::internal::Object> obj) :
  current_revision_(revision), obj_(obj) {}

int ObjectSnapshot::GetCurrentRevision() const {
  return current_revision_;
}

v8::internal::Handle<v8::internal::Object> ObjectSnapshot::GetObj() const {
  return obj_;
}

TaggedObject::TaggedObject(
    v8::internal::Handle<v8::internal::Object> sn, int uniqueid) :
  obj_(sn), unique_id_(uniqueid) {}

int TaggedObject::GetUniqueId() const {
  return unique_id_;
}

v8::internal::Handle<v8::internal::Object> TaggedObject::GetObj() const {
  return obj_;
}

RevisionDictionary::RevisionDictionary() : dict_() {}
RevisionDictionary::RevisionDictionary(
    v8::internal::Handle<v8::internal::NameDictionary> dict) :
  dict_(dict) {}

RevisionDictionary::RevisionDictionary(
    v8::internal::Isolate* isolate, int size) :
  dict_(NameDictionary::New(isolate, size)) {}


v8::internal::MaybeHandle<v8::internal::Object> RevisionDictionary::Lookup(
    v8::internal::Handle<v8::internal::Name> key) {
  UNREACHABLE();
}

void RevisionDictionary::Put(v8::internal::Handle<v8::internal::Name>,
                             v8::internal::Handle<v8::internal::Object>) {
  UNREACHABLE();
}

bool RevisionDictionary::IsValid() {
  return false;
}

TaggedRevisedObject::TaggedRevisedObject(
      v8::internal::Handle<v8::internal::JSReceiver> rec,
      int unique_id,
      int revision,
      RevisionDictionary revisions) :
  obj_(rec),
  unique_id_(unique_id),
  revision_(revision),
  revisions_(revisions) {}


v8::internal::Handle<v8::internal::JSReceiver>
TaggedRevisedObject::GetTarget() const {
  return obj_;
}

int TaggedRevisedObject::GetId() const {
  return unique_id_;
}

int TaggedRevisedObject::GetVersion() const {
  return revision_;
}

const RevisionDictionary& TaggedRevisedObject::GetRevisions() const {
  return revisions_;
}





RevisionInfo::RevisionInfo(
    v8::internal::Handle<v8::internal::ArrayList> holder, int index) :
  holder_(holder), base_index_(index) {}

v8::internal::Object* RevisionInfo::GetIndexOffset(int offset) const {
  return holder_->Get(base_index_ + offset);
}

int RevisionInfo::GetIndexOffsetSmi(int offset) const {
  Object* obj = GetIndexOffset(offset);
  DCHECK(obj->IsSmi());
  return Smi::cast(obj)->value();
}

int RevisionInfo::GetRevisionNumber() const {
  return GetIndexOffsetSmi(IDX_REVISION_NUMBER);
}

RevisionInfo::Type RevisionInfo::GetType() const {
  return static_cast<Type>(GetIndexOffsetSmi(IDX_REVISION_TYPE));
}

v8::internal::String* RevisionInfo::GetKey() const {
  Object* obj = GetIndexOffset(IDX_REVISION_KEY);
  DCHECK(obj->IsString());
  return String::cast(obj);
}

v8::internal::Object* RevisionInfo::GetPrevVal() const {
  return GetIndexOffset(IDX_REVISION_VALUE);
}

bool RevisionInfo::HasBeenSerialized() const {
  return SerializedUniqueId() !=
    HAS_NOT_BEEN_SERIALIZED;
}

int RevisionInfo::SerializedUniqueId() const {
  return GetIndexOffsetSmi(IDX_HAS_BEEN_SERIALIZED);
}


void RevisionInfo::SetRevisionNumber(int number) {
  SetIndexOffset(number, IDX_REVISION_NUMBER);
}

void RevisionInfo::SetType(Type type) {
  SetIndexOffset(static_cast<int>(type), IDX_REVISION_TYPE);
}

void RevisionInfo::SetKey(v8::internal::String* obj) {
  SetIndexOffset(obj, IDX_REVISION_KEY);
}

void RevisionInfo::SetValue(v8::internal::Object* obj) {
  SetIndexOffset(obj, IDX_REVISION_VALUE);
}

void RevisionInfo::SetIndexOffset(int obj, int offset) {
  SetIndexOffset(Smi::FromInt(obj), offset);
}

void  RevisionInfo::SetIndexOffset(Object* obj, int offset) {
  holder_->Set(base_index_ + offset, obj);
}

void RevisionInfo::SetSerializedUniqueId(int obj) {
  SetIndexOffset(Smi::FromInt(obj), IDX_HAS_BEEN_SERIALIZED);
}


ImmutableRevisionList::Iterator::Iterator(int index) : index_(index) {}

ImmutableRevisionList::Iterator
ImmutableRevisionList::Iterator::Increment() const {
  return Iterator(index_ + 1);
}

int ImmutableRevisionList::Iterator::Difference(const Iterator& other) const {
  return index_ - other.index_;
}

ImmutableRevisionList::Iterator
ImmutableRevisionList::Iterator::Decrement() const {
  return Iterator(index_ - 1);
}

bool ImmutableRevisionList::Iterator::operator==(const Iterator& other) const {
  return index_ == other.index_;
}

bool ImmutableRevisionList::Iterator::operator!=(const Iterator& other) const {
  return index_ != other.index_;
}

bool ImmutableRevisionList::Iterator::operator<=(
    const Iterator& other) const {
  return index_ <= other.index_;
}

bool ImmutableRevisionList::Iterator::operator>=(
    const Iterator& other) const {
  return index_ >= other.index_;
}

ImmutableRevisionList::Iterator ImmutableRevisionList::Iterator::Between(
    const Iterator& other) const {
  return Iterator((index_ + other.index_) / 2);
}

int ImmutableRevisionList::Iterator::BaseIndex() const {
  return (index_ * RevisionInfo::IDX_SIZE) +
    ImmutableRevisionList::REVISION_SIZE_IDX;
}


ImmutableRevisionList::ImmutableRevisionList(
    v8::internal::Handle<v8::internal::ArrayList> mem) :
  mem_(mem) {}

ImmutableRevisionList::Iterator ImmutableRevisionList::begin() const {
  return Iterator(0);
}

ImmutableRevisionList::Iterator ImmutableRevisionList::end() const {
  return Iterator(mem_->Length());
}

RevisionInfo ImmutableRevisionList::GetRevisionInfo(Iterator pos) const {
  DCHECK(pos.index_ < mem_->Length());
  return RevisionInfo (mem_, pos.BaseIndex());
}


ImmutableRevisionList::Iterator ImmutableRevisionList::RevisionAt(
    int revision_number) const {
  Iterator left = begin();
  Iterator right = end().Decrement();

  // In the case where left is already greater than the target, this will
  // return the wrong value, but we would want to serialize all the records
  // anyway, so we don't check for that here.
  Iterator closest_without_going_over = left;

  while (left <= right) {
    Iterator middle = left.Between(right);
    RevisionInfo info (mem_, middle.BaseIndex());
    int value = info.GetRevisionNumber();
    if (value < revision_number) {
      closest_without_going_over = middle;
      right = middle.Decrement();
    } else if (value > revision_number) {
      left = middle.Increment();
    } else {
      return middle;
    }
  }

  return closest_without_going_over;
}

// static
v8::internal::Handle<v8::internal::ArrayList> ImmutableRevisionList::NewList(
    v8::internal::Isolate* isolate) {
  Handle<ArrayList> value = Handle<ArrayList>::cast(
      isolate->factory()->NewFixedArray(0));
  value = ArrayList::Add(value, handle(Smi::FromInt(NO_REVISION), isolate));
  return value;
}



// static
v8::internal::Handle<v8::internal::ArrayList>
ImmutableRevisionList::AppendToMemory(
    Handle<ArrayList> mem,
    int revision,
    RevisionInfo::Type type,
    Handle<String> key,
    Handle<Object> val) {
  Isolate* isolate = mem->GetIsolate();
  Handle<Object> the_hole (isolate->heap()->the_hole_value(), isolate);
  int length = mem->Length();

  Handle<ArrayList> ret_val;
  for (int i = 0; i < RevisionInfo::IDX_SIZE; i++) {
    ret_val = ArrayList::Add(mem, the_hole);
  }

  RevisionInfo info (ret_val, length);
  info.SetRevisionNumber(revision);
  info.SetType(type);
  info.SetKey(*key);
  info.SetValue(*val);
  info.SetSerializedUniqueId(RevisionInfo::HAS_NOT_BEEN_SERIALIZED);

  return ret_val;
}




ObjectVersioner::ObjectVersioner(v8::internal::Isolate* isolate) :
  weak_object_map_(),
  current_version_(1),
  unique_immutable_id_(1),
  isolate_(isolate) {}

void ObjectVersioner::Init() {
  static const int INITIAL_OBJECT_MAP_SIZE = 16;

  weak_object_map_.reset(
      new LiteralValueHolder(
          WeakHashTable::New(isolate_, INITIAL_OBJECT_MAP_SIZE), isolate_));
}

void ObjectVersioner::OnSet(
    v8::internal::Handle<v8::internal::JSReceiver> target,
    v8::internal::Handle<v8::internal::String> key,
    v8::internal::Handle<v8::internal::Object> prev_value) {
  AppendNewRevision(target, RevisionInfo::REPLACE, key, prev_value);
}

void ObjectVersioner::OnRemove(
    v8::internal::Handle<v8::internal::JSReceiver> target,
    v8::internal::Handle<v8::internal::String> key,
    v8::internal::Handle<v8::internal::Object> prev_value) {
  AppendNewRevision(target, RevisionInfo::DELETE, key, prev_value);
}

void ObjectVersioner::OnAppend(
    v8::internal::Handle<v8::internal::JSReceiver> target,
    v8::internal::Handle<v8::internal::String> key) {
  AppendNewRevision(
      target, RevisionInfo::APPEND, key,
      handle(isolate_->heap()->the_hole_value(), isolate_));
}

void ObjectVersioner::AppendNewRevision(
    v8::internal::Handle<v8::internal::JSReceiver> target,
    RevisionInfo::Type type,
    v8::internal::Handle<v8::internal::String> key,
    v8::internal::Handle<v8::internal::Object> prev_value) {
  Handle<Object> prev_table = handle(GetTable()->Lookup(target), isolate_);

  int new_version = ++current_version_;
  if (prev_table->IsFixedArray()) {
    DCHECK(prev_table->IsArrayList());

    Handle<ArrayList> new_table = ImmutableRevisionList::AppendToMemory(
        Handle<ArrayList>::cast(prev_table),
        new_version, type, key, prev_value);
    if (*new_table != *prev_table) {
      PutInMap(target, new_table);
    }
  } else {
    PutInMap(
        target,
        ImmutableRevisionList::AppendToMemory(
            ImmutableRevisionList::NewList(isolate_),
            new_version,
            type,
            key,
            prev_value));
  }
}

void ObjectVersioner::PutInMap(
    v8::internal::Handle<v8::internal::HeapObject> target,
    v8::internal::Handle<v8::internal::HeapObject> value) {
  Handle<WeakHashTable> old_table = GetTable();
  Handle<WeakHashTable> new_table = WeakHashTable::Put(
      old_table, target, value);

  if (*new_table != *old_table) {
    weak_object_map_.reset(new LiteralValueHolder(new_table, isolate_));
  }
}

v8::internal::Handle<v8::internal::WeakHashTable> ObjectVersioner::GetTable() {
  if (!weak_object_map_) {
    Init();
  }

  return Handle<WeakHashTable>::cast(weak_object_map_->Get());
}

Status ObjectVersioner::MaybeSerialize(
    ObjectSnapshot target_snap,
    Ast::JsObjectValue::Builder builder,
    MessageHolder& holder) {
  int revision = target_snap.GetCurrentRevision();

  DCHECK(revision <= current_version_);
  DCHECK(target_snap.GetObj()->IsHeapObject());
  auto target = Handle<HeapObject>::cast(target_snap.GetObj());

  InstanceType type = target->map()->instance_type();
  if (type == ODDBALL_TYPE) {
    return holder.WriteConcreteImmutableObjectSlow(
        builder, TaggedObject (target, TaggedObject::NO_ID));
  }

  Handle<Object> lookup_val =
    handle(GetTable()->Lookup(Handle<HeapObject>::cast(target)), isolate_);

  // If the target is a receiver, then we must look up its revision in the
  // revision list and serialize all the changes since the object was last
  // serialized.
  if (target->IsJSReceiver()) {
    Handle<JSReceiver> as_receiver = Handle<JSReceiver>::cast(target);

    if (lookup_val->IsArrayList()) {
      ImmutableRevisionList list (Handle<ArrayList>::cast(lookup_val));
      ImmutableRevisionList::Iterator find = list.RevisionAt(revision);
      RevisionInfo find_info = list.GetRevisionInfo(find);

      if (find_info.HasBeenSerialized()) {
        builder.setUniqueId(find_info.SerializedUniqueId());
        builder.getValue().setPreviouslySerialized();
        return Status::OK;

      } else {

        // We have a JSReceiver with
        ImmutableRevisionList::Iterator end = list.end();
        RevisionDictionary revisions (isolate_, end.Difference(find));
        while (end != find) {
          RevisionInfo info = list.GetRevisionInfo(end);
          DCHECK(info.GetKey()->IsString());
          revisions.Put(
              Handle<String> (info.GetKey(), isolate_),
              handle(info.GetPrevVal(), isolate_));
          end = end.Decrement();
        }

        int new_id = ++unique_immutable_id_;
        find_info.SetSerializedUniqueId(new_id);
        return holder.WriteConcreteReceiverSlow(
            builder,
            TaggedRevisedObject (as_receiver, new_id, revision, revisions));
      }

    } else {

      if (lookup_val->IsTheHole(isolate_)) {
        // We don't have any revisions for this object, so just tag and serialize
        // it.

        unique_immutable_id_ += 1;
        TaggedObject tag (as_receiver, unique_immutable_id_);
        PutInMap(as_receiver,
                 isolate_->factory()->NewHeapNumber(tag.GetUniqueId()));
        return holder.WriteConcreteReceiverSlow(
            builder,
            TaggedRevisedObject(
                as_receiver,
                tag.GetUniqueId(),
                revision,
                RevisionDictionary()));
      } else {
        int32_t value;
        CHECK(lookup_val->ToInt32(&value));
        builder.setUniqueId(value);
        builder.getValue().setPreviouslySerialized();
        return Status::OK;
      }
    }

  } else {
    // !target->IsJSReceiver
    //
    // This means that we check if the object has been serialized before.

    if (lookup_val->IsTheHole(isolate_)) {
      // The object has not been serialized before, so we serialize it, then
      // store the unique id in the map if the serialization succeeded.
      unique_immutable_id_ += 1;
      TaggedObject tag (target, unique_immutable_id_);
      if (holder.WriteConcreteImmutableObjectSlow(builder, tag)) {
        PutInMap(
            target, isolate_->factory()->NewHeapNumber(tag.GetUniqueId()));
        return Status::OK;
      } else {
        return Status::FAILURE;
      }
    } else {
      // The object has been serialized before, so we mark the object with the
      // unique id.
      int32_t value;
      CHECK(lookup_val->ToInt32(&value));
      builder.setUniqueId(value);
      builder.getValue().setPreviouslySerialized();
      return Status::OK;
    }
  }
}

ObjectVersioner& ObjectVersioner::FromIsolate(
    v8::internal::Isolate* isolate) {
  return TaintTracker::FromIsolate(isolate)->Get()->Versioner();
}



}
