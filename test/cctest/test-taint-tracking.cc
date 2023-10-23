#include "test/cctest/cctest.h"

#include "src/objects-inl.h"
#include "src/taint_tracking.h"
#include "src/taint_tracking-inl.h"
#include "src/taint_tracking/log_listener.h"
#include "src/uri.h"

#include <memory>
#include <vector>
#include <string>
#include <stdio.h>

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <kj/std/iostream.h>
#include <capnp/pretty-print.h>

using namespace v8::internal;
using namespace tainttracking;


class TestCase {
public:
  TestCase() {
    CcTest::InitializeVM();
  }

  ~TestCase() {}
};

TEST(TaintLarge) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Factory* factory = CcTest::i_isolate()->factory();
  Handle<String> test = factory->NewStringFromStaticChars(
      "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdf");
  CHECK_EQ(GetTaintStatus(*test, 2), TaintType::UNTAINTED);
  SetTaintStatus(*test, 2, TaintType::TAINTED);
  SetTaintStatus(*test, 0, TaintType::TAINTED);
  SetTaintStatus(*test, 39, TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*test, 2), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*test, 0), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*test, 39), TaintType::TAINTED);
  std::unique_ptr<char[]> value = test->ToCString();
  CHECK_EQ(strcmp(value.get(), "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdf"), 0);
  CHECK_EQ(test->length(), 40);
}

TEST(TaintLargeModOne) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Factory* factory = CcTest::i_isolate()->factory();
  Handle<String> test = factory->NewStringFromStaticChars(
      "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfa");
  CHECK_EQ(GetTaintStatus(*test, 2), TaintType::UNTAINTED);
  CHECK_EQ(GetTaintStatus(*test, 40), TaintType::UNTAINTED);
  CHECK_EQ(GetTaintStatus(*test, 5), TaintType::UNTAINTED);
  SetTaintStatus(*test, 2, TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*test, 2), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*test, 40), TaintType::UNTAINTED);
  CHECK_EQ(GetTaintStatus(*test, 5), TaintType::UNTAINTED);
}

TEST(TaintConsStringSelf) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Factory* factory = CcTest::i_isolate()->factory();
  Handle<String> test = factory->NewStringFromStaticChars(
      "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfa");
  SetTaintStatus(*test, 2, TaintType::TAINTED);

  Handle<String> cons = factory->NewConsString(test, test).ToHandleChecked();
  CHECK_EQ(GetTaintStatus(*cons, 3), TaintType::UNTAINTED);
  SetTaintStatus(*cons, 3, TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*cons, 3), TaintType::TAINTED);

  // Setting taint status on parent should flow through the Cons
  CHECK_EQ(GetTaintStatus(*cons, 2), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*cons, 43), TaintType::TAINTED);
}

TEST(TaintConsStringTwo) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Factory* factory = CcTest::i_isolate()->factory();
  Handle<String> first = factory->NewStringFromStaticChars("firstfirstfirst");
  Handle<String> second =
    factory->NewStringFromStaticChars("secondsecondsecond");
  SetTaintStatus(*first, 2, TaintType::TAINTED);
  SetTaintStatus(*second, 2, TaintType::TAINTED);

  Handle<String> cons = factory->NewConsString(first, second).ToHandleChecked();
  CHECK_EQ(GetTaintStatus(*cons, 3), TaintType::UNTAINTED);
  SetTaintStatus(*cons, 3, TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*cons, 3), TaintType::TAINTED);

  // Setting taint status on parent should flow through the Cons
  CHECK_EQ(GetTaintStatus(*cons, 2), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*cons, 17), TaintType::TAINTED);

  Handle<String> flat = String::Flatten(cons);
  CHECK_EQ(GetTaintStatus(*flat, 2), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*flat, 17), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*flat, 3), TaintType::TAINTED);
}

TEST(TaintConsStringShort) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Factory* factory = CcTest::i_isolate()->factory();
  Handle<String> first = factory->NewStringFromStaticChars("fir");
  Handle<String> second = factory->NewStringFromStaticChars("sec");
  SetTaintStatus(*first, 2, TaintType::TAINTED);
  SetTaintStatus(*second, 2, TaintType::TAINTED);

  Handle<String> cons = factory->NewConsString(first, second).ToHandleChecked();
  CHECK_EQ(GetTaintStatus(*cons, 3), TaintType::UNTAINTED);
  CHECK_EQ(GetTaintStatus(*cons, 2), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*cons, 5), TaintType::TAINTED);
  SetTaintStatus(*cons, 3, TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*cons, 3), TaintType::TAINTED);

  // Setting taint status on parent should flow through the Cons
  CHECK_EQ(GetTaintStatus(*cons, 2), TaintType::TAINTED);

  Handle<String> flat = String::Flatten(cons);
  CHECK_EQ(GetTaintStatus(*flat, 2), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*flat, 3), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*flat, 5), TaintType::TAINTED);
}

TEST(TaintConsStringTwoChar) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Factory* factory = CcTest::i_isolate()->factory();
  Handle<String> first = factory->NewStringFromStaticChars("f");
  Handle<String> second = factory->NewStringFromStaticChars("s");
  SetTaintStatus(*first, 0, TaintType::TAINTED);
  SetTaintStatus(*second, 0, TaintType::TAINTED);

  Handle<String> cons = factory->NewConsString(first, second).ToHandleChecked();
  CHECK_EQ(GetTaintStatus(*cons, 0), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*cons, 1), TaintType::TAINTED);
}

TEST(TaintConcatStringContent) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Factory* factory = CcTest::i_isolate()->factory();
  const uint16_t two_byte_str[] = {0x0024, 0x20AC, 0x0064};
  Handle<String> first = factory->NewStringFromTwoByte(
      Vector<const uc16>(two_byte_str, 3)).ToHandleChecked();
  Handle<String> second = factory->NewStringFromTwoByte(
      Vector<const uc16>(two_byte_str, 3)).ToHandleChecked();
  SetTaintStatus(*first, 0, TaintType::TAINTED);
  SetTaintStatus(*second, 0, TaintType::TAINTED);

  Handle<String> cons = factory->NewConsString(first, second).ToHandleChecked();
  CHECK(cons->IsTwoByteRepresentation());
  CHECK(cons->IsSeqString());
  CHECK_EQ(GetTaintStatus(*cons, 0), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*cons, 3), TaintType::TAINTED);
}

TEST(TaintSlicedString) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Factory* factory = CcTest::i_isolate()->factory();
  Handle<String> parent = factory->NewStringFromStaticChars(
      "parentparentparent");
  SetTaintStatus(*parent, 2, TaintType::TAINTED);

  Handle<String> slice = factory->NewSubString(parent, 1, 17);
  CHECK_EQ(GetTaintStatus(*slice, 3), TaintType::UNTAINTED);
  SetTaintStatus(*slice, 3, TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*slice, 3), TaintType::TAINTED);

  // Setting taint status on parent should flow through the Cons
  CHECK_EQ(GetTaintStatus(*slice, 1), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*slice, 15), TaintType::UNTAINTED);

  Handle<String> flat = String::Flatten(slice);
  CHECK_EQ(GetTaintStatus(*flat, 1), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*flat, 15), TaintType::UNTAINTED);
}

TEST(TaintSlicedStringOne) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Factory* factory = CcTest::i_isolate()->factory();
  Handle<String> parent = factory->NewStringFromStaticChars(
      "parentparentparent");
  SetTaintStatus(*parent, 1, TaintType::TAINTED);
  Handle<String> slice = factory->NewSubString(parent, 1, 2);
  CHECK_EQ(GetTaintStatus(*slice, 0), TaintType::TAINTED);
}

TEST(TaintSlicedStringTwo) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Factory* factory = CcTest::i_isolate()->factory();
  Handle<String> parent = factory->NewStringFromStaticChars(
      "parentparentparent");
  SetTaintStatus(*parent, 1, TaintType::TAINTED);
  Handle<String> slice = factory->NewSubString(parent, 1, 3);
  CHECK_EQ(GetTaintStatus(*slice, 0), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*slice, 1), TaintType::UNTAINTED);
}

TEST(TaintEncodingUriComponent) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  // Test encoding and decoding for normal characters
  Handle<String> target = factory->NewStringFromStaticChars(
      "astringwithspecial!;.;\"\'=-&");
  SetTaintStatus(*target, 0, TaintType::TAINTED);
  Handle<String> encoded = Uri::EncodeUriComponent(isolate, target)
    .ToHandleChecked();
  CHECK_EQ(GetTaintStatus(*encoded, 0),
           TaintType::TAINTED | TaintType::URL_COMPONENT_ENCODED);
  CHECK_EQ(GetTaintStatus(*encoded, 1),
           TaintType::UNTAINTED | TaintType::URL_COMPONENT_ENCODED);

  Handle<String> decoded = Uri::DecodeUriComponent(isolate, encoded)
    .ToHandleChecked();
  CHECK_EQ(decoded->length(), target->length());
  CHECK_EQ(GetTaintStatus(*decoded, 0), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*decoded, 1), TaintType::UNTAINTED);


  // Test the tainting of encoded characters
  target = factory->NewStringFromStaticChars(
      "astringwithspecial&");
  SetTaintStatus(*target, 18, TaintType::TAINTED); // The & character
  encoded = Uri::EncodeUriComponent(isolate, target)
    .ToHandleChecked();
  CHECK_EQ(encoded->length(), 21); // Check that the & expands two characters
  CHECK_EQ(GetTaintStatus(*encoded, 18),
           TaintType::TAINTED | TaintType::URL_COMPONENT_ENCODED);
  CHECK_EQ(GetTaintStatus(*encoded, 19),
           TaintType::TAINTED | TaintType::URL_COMPONENT_ENCODED);
  CHECK_EQ(GetTaintStatus(*encoded, 20),
           TaintType::TAINTED | TaintType::URL_COMPONENT_ENCODED);

  decoded = Uri::DecodeUriComponent(isolate, encoded)
    .ToHandleChecked();
  CHECK_EQ(decoded->length(), target->length());
  CHECK_EQ(GetTaintStatus(*decoded, 18), TaintType::TAINTED);

  decoded = Uri::DecodeUri(isolate, encoded)
    .ToHandleChecked();
  CHECK_EQ(GetTaintStatus(*decoded, 18),
           TaintType::TAINTED | TaintType::MULTIPLE_ENCODINGS);
}

class TestTaintListener : public TaintListener {
public:
  ~TestTaintListener() override {}

  void OnTaintedCompilation(const TaintInstanceInfo& info,
                            v8::internal::Isolate* isolate) override {
    scripts_.push_back("");
  }

  std::vector<std::string> GetScripts() {
    return scripts_;
  }

private:
  std::vector<std::string> scripts_;
};

TEST(OnBeforeCompile) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(CcTest::isolate(), "var a = 1;");
  Handle<String> source_h = v8::Utils::OpenHandle(*source);
  SetTaintStatus(*source_h, 0, TaintType::TAINTED);
  CHECK_EQ(CheckTaint(*source_h), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*source_h, 0), TaintType::TAINTED);
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  v8::MaybeLocal<v8::Script> result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source);
  CHECK_EQ(listener->GetScripts().size(), 1);
}

v8::MaybeLocal<v8::Value> TestCompile(
    TestTaintListener* listener, const char* source_code, int taint_location) {
  v8::Local<v8::String> source = v8_str(CcTest::isolate(), source_code);
  Handle<String> source_h = v8::Utils::OpenHandle(*source);
  SetTaintStatus(*source_h, taint_location, TaintType::TAINTED);
  CHECK_EQ(CheckTaint(*source_h), TaintType::TAINTED);
  CHECK_EQ(GetTaintStatus(*source_h, taint_location), TaintType::TAINTED);
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  return v8::Script::Compile(context, source)
    .ToLocalChecked()->Run(context);
}

TEST(OnBeforeCompileEval) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  TestTaintListener* listener = new TestTaintListener();
  auto value = TestCompile(
      listener, "var a = '1 + 1'; var b = eval(a); b", 9).ToLocalChecked();
  CHECK_GT(listener->GetScripts().size(), 0);
  CHECK_EQ(
      2, value->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(OnBeforeCompileFunction) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  TestTaintListener* listener = new TestTaintListener();
  auto value = TestCompile(
      listener, "var a = 'return 1 + 1;'; (new Function(a))();", 9);
  CHECK_GT(listener->GetScripts().size(), 0);
}

TEST(OnBeforeCompileEvalNonTainted) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  TestTaintListener* listener = new TestTaintListener();
  auto value = TestCompile(
      listener, "var a = '1 + 1;'; eval(a);", 0).ToLocalChecked();
  CHECK_GT(listener->GetScripts().size(), 0);
  CHECK_EQ(
      2, value->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(OnBeforeCompileSetTaint) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(), "var a = '1 + 1'; a.__setTaint__(1); eval(a);");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
  CHECK_EQ(
      2, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(OnBeforeCompileGetTaint) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1 + 1'; "
      "new Uint8Array(a.__getTaint__(1))[0]; ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      0, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(OnBeforeCompileGetSetTaint) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1 + 1'; "
      "a.__setTaint__(1); "
      "new Uint8Array(a.__getTaint__())[0]; ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      1, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(OnBeforeCompileGetSetTaintByteArray) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1 + 1'; "
      "var c = a.__getTaint__(); "
      "var b = new Uint8Array(c); "
      "b[0] = 1; "
      "a.__setTaint__(c); "
      "eval(a); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
  CHECK_EQ(
      2, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(RecursiveTaintObjectSimple) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = {'key': '2'};"
      "__setTaint__(a, 1);"
      "eval(a.key);");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))
    ->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
  CHECK_EQ(2, result->Int32Value(
               CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(RecursiveTaintObjectRecursive) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = {'key': {'kv': '2'}};"
      "__setTaint__(a, 1);"
      "eval(a.key.kv);");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))
    ->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
  CHECK_EQ(2, result->Int32Value(
               CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(RecursiveTaintObjectArray) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = {'key': ['1', '2']};"
      "__setTaint__(a, 1);"
      "eval(a.key[1]);");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))
    ->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
  CHECK_EQ(2, result->Int32Value(
               CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(OnBeforeCompileGetSetTransitiveTaintByteArray) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1 + 1'; "
      "a.__setTaint__(1);"
      "b = 'var d = ' + a + '; d;';"
      "eval(b); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
  CHECK_EQ(
      2, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(OnBeforeCompileGetSetSliceTaintByteArray) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1 + 11'; "
      "a.__setTaint__(1);"
      "eval(a.substring(0, 5)); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      2, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(OnBeforeCompileGetSetSliceSingleTaintByteArray) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1 + 11'; "
      "a.__setTaint__(1);"
      "eval(a.substring(0, 1)); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      1, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(OnBeforeCompileGetSetConsSingleTaintByteArray) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1'; "
      "a.__setTaint__(1);"
      "eval(a + '2'); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      12,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_EQ(listener->GetScripts().size(), 1);
}

class TaintOneByteResource :
  public v8::String::ExternalOneByteStringResource,
  public v8::String::TaintTrackingStringBufferImpl {
public:
  TaintOneByteResource(const char* data, size_t length)
    : data_(data), length_(length) {}
  ~TaintOneByteResource() { i::DeleteArray(data_); }
  virtual const char* data() const { return data_; }
  virtual size_t length() const { return length_; }

private:
  const char* data_;
  size_t length_;
};

TEST(SubStringExternalStringShort) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  LocalContext context;
  char* one_byte_res = new char[2];
  *one_byte_res = '2';
  *(one_byte_res + 1) = '2';
  TaintOneByteResource* one_byte_resource = new TaintOneByteResource(
      one_byte_res, sizeof(one_byte_res));
  v8::Local<v8::String> one_byte_external_string =
    v8::String::NewExternalOneByte(CcTest::isolate(), one_byte_resource)
    .ToLocalChecked();
  v8::Local<v8::Object> global = context->Global();
  global->Set(context.local(), v8_str("ext_one_byte"), one_byte_external_string)
    .FromJust();
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "ext_one_byte.__setTaint__(1);"
      "eval(ext_one_byte.substring(0, 1)); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      2, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintFlagToString) {
  CHECK_EQ(TaintTypeToString(TaintType::UNTAINTED), "Untainted");
  CHECK_EQ(TaintTypeToString(TaintType::URL), "Url");
  CHECK_EQ(
      TaintFlagToString(AddFlag(AddFlag(0, TaintType::URL), TaintType::DOM)),
      "Url&Dom");
  CHECK_EQ(
      TaintFlagToString(AddFlag(0, TaintType::WINDOWNAME)),
      "WindowName");
  CHECK_EQ(
      TaintFlagToString(AddFlag(AddFlag(0, TaintType::URL), TaintType::COOKIE)),
      "Cookie&Url");
}

TEST(TaintUrlEscapeRaw) {
  TestCase test_case;
  Factory* factory = CcTest::i_isolate()->factory();
  v8::HandleScope scope(CcTest::isolate());
  Handle<String> test = factory->NewStringFromStaticChars("0 0 0 a");
  SetTaintStatus(*test, 0, TaintType::TAINTED);
  SetTaintStatus(*test, 1, TaintType::TAINTED);
  SetTaintStatus(*test, 5, TaintType::TAINTED);

  Handle<String> encoded = Uri::Escape(
      CcTest::i_isolate(), test).ToHandleChecked();
  CHECK_EQ(13, encoded->length());
  CHECK_EQ(GetTaintStatus(*encoded, 0),
           TaintType::TAINTED | TaintType::ESCAPE_ENCODED);
  CHECK_EQ(GetTaintStatus(*encoded, 1),
           TaintType::TAINTED | TaintType::ESCAPE_ENCODED);
  CHECK_EQ(GetTaintStatus(*encoded, 2),
           TaintType::TAINTED | TaintType::ESCAPE_ENCODED);
  CHECK_EQ(GetTaintStatus(*encoded, 3),
           TaintType::TAINTED | TaintType::ESCAPE_ENCODED);
  CHECK_EQ(GetTaintStatus(*encoded, 4),
           TaintType::UNTAINTED | TaintType::ESCAPE_ENCODED);
  CHECK_EQ(GetTaintStatus(*encoded, 11),
           TaintType::TAINTED | TaintType::ESCAPE_ENCODED);
  CHECK_EQ(GetTaintStatus(*encoded, 12),
           TaintType::UNTAINTED | TaintType::ESCAPE_ENCODED);
}

TEST(TaintUrlEscape) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1 + 1'; "
      "a.__setTaint__(1); "
      "eval('\"' + escape(a) + '\"'); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintUrlUnescape) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1%20%2B%201'; " // var a = '1 + 1'
      "a.__setTaint__(1); "
      "eval(unescape(a)); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
  CHECK_EQ(
      2, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(TaintUrlEncode) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1 + 1'; "
      "a.__setTaint__(1); "
      "eval('\"' + encodeURI(a) + '\"'); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintUrlUnencode) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '1%20%2B%201'; " // var a = '1 + 1'
      "a.__setTaint__(1); "
      "eval('\"' + decodeURI(a) + '\"'); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintJoinElem) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = ['1', '1', '1']; "
      "a[0].__setTaint__(1); "
      "eval(a.join(' + ')); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
  CHECK_EQ(
      3, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(TaintJoinSparseElem) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = ['1',,,,,,,,,,,,,,,,,,,'1']; "
      "a[0].__setTaint__(1); "
      "eval(a.join('')); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      11,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintJoinSparseElemSep) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = [,,,,,,,,,,,,,,'2',,]; "
      "a[14].__setTaint__(1); "
      "for (var i = 0; i < 1000; i++) {a = [,,,,,].concat(a)}"
      "eval(a.join('0')); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      16,                       // Leading 0's are interpreted as hexadecimal
      result->IntegerValue(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintJoinSep) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = ['1', '1', '1']; "
      "b = '+';"
      "b.__setTaint__(1);"
      "eval(a.join(b)); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
  CHECK_EQ(
      3, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(TaintRegexp) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = /as/g;"
      "var b = 'asdf';"
      "b.__setTaint__(1);"
      "b.replace(a, '$&');"
      "eval('\"' + b + '\"');");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintRegexpSimple) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = /as/g;"
      "var b = 'asdf';"
      "b.__setTaint__(1);"
      "b.replace(a, 'jfj');"
      "eval('\"' + b + '\"');");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintJSONStringify) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = { 'asdf' : '1' }; "
      "Object.keys(a)[0].__setTaint__(1); "
      "a['asdf'].__setTaint__(1);"
      "eval('\"' + JSON.stringify(a) + '\"'); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintJSONParse) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '{ \"asdf\" : \"1\" }'; "
      "a.__setTaint__(1);"
      "var b = JSON.parse(a);"
      "eval(b.asdf); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintStringUpper) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = 'aaaaa'; "
      "a.__setTaint__(1);"
      "eval('\"' + a.toUpperCase() + '\"'); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintStringLower) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = 'AAAAA'; "
      "a.__setTaint__(1);"
      "eval('\"' + a.toLowerCase() + '\"'); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintStringSplit) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '2 a a a a'; "
      "a.__setTaint__(1);"
      "eval(a.split(' ')[0]); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
  CHECK_EQ(
      2, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(TaintStringLocaleUpper) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = 'aaaaa'; "
      "a.__setTaint__(1);"
      "eval('\"' + a.toLocaleUpperCase() + '\"'); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintStringLocaleLower) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = 'AAAAA'; "
      "a.__setTaint__(1);"
      "eval('\"' + a.toLocaleLowerCase() + '\"'); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 1);
}

TEST(TaintStringCharAt) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = '2sdfasdf'; "
      "a.__setTaint__(1);"
      "var b = a.charAt(0);"
      "eval(b); ");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->
    RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();

  // Ideally, this would be 1, but now we just want to make sure it doesn't
  // crash
  CHECK_EQ(listener->GetScripts().size(), 0);
  CHECK_EQ(
      2, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

TEST(TaintStringFromCharCodeAt) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "function a(val) {"
      "  var a = String.fromCharCode(val); " // An 'A'
      "  a.__checkTaint__(a[0]);"
      "}"
      "for (var j = 0; j < 10000; j++){"
      "  a((j % 32) + 60);"
      "}"
      "2;");
  TestTaintListener* listener = new TestTaintListener();
  CHECK_EQ(listener->GetScripts().size(), 0);
  TaintTracker::FromIsolate(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()))->
    RegisterTaintListener(listener);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(listener->GetScripts().size(), 0);
  CHECK_EQ(
      2, result->Int32Value(
          CcTest::isolate()->GetCurrentContext()).FromJust());
}


TEST(ControlFlowLog) {
  FLAG_taint_tracking_enable_export_ast = true;
  FLAG_taint_tracking_enable_ast_modification = true;
 TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = 'a'; "
      "var ret = 1; "
      "if (a == 'a') {"
      "  ret = 2;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      2, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
}

class AstListener : public tainttracking::LogListener {
public:
  AstListener() {}
  virtual ~AstListener() {}
  virtual void OnLog(const ::TaintLogRecord::Reader& message) override {
    // TODO: how to store?
    if (message.getMessage().which() == ::TaintLogRecord::Message::AST) {
      num += 1;
      auto ast = message.getMessage().getAst();
      CHECK(ast.hasRoot());
    }
  }

  int num = 0;
};

TEST(AstExportNoModification) {
  FLAG_taint_tracking_enable_export_ast = true;
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  AstListener* listener = new AstListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = 'a'; "
      "var ret = 2;"
      "for (var i = 0; i < 8; i++) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      10, result->Int32Value(
          CcTest::isolate()->GetCurrentContext()).FromJust());

  CHECK_GE(listener->num, 1);
}

TEST(AstExportWithModification) {
  FLAG_taint_tracking_enable_export_ast = true;
  FLAG_taint_tracking_enable_ast_modification = true;
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  AstListener* listener = new AstListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = 'a'; "
      "var ret = 1; "
      "if (a == 'a') {"
      "  ret = 2;"
      "}"
      "var test_arr = [];"
      "test_arr = [1, 2];"
      "var ttt = {'asf': 1};"
      "for (var i = 0; i < 2; i++) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      4, result->Int32Value(
          CcTest::isolate()->GetCurrentContext()).FromJust());

  CHECK_GE(listener->num, 1);
}

TEST(AstExportMethodCallWithModification) {
  FLAG_taint_tracking_enable_export_ast = true;
  FLAG_taint_tracking_enable_ast_modification = true;
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  AstListener* listener = new AstListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var ret = 1;"
      "var a = {addthree: function() {return this.three;}};"
      "a.three = 3;"
      "ret += a.addthree();"
      "ret;");
  auto ctx = CcTest::isolate()->GetCurrentContext();
  auto result = v8::Script::Compile(ctx, source).ToLocalChecked()->Run();
  CHECK_EQ(4, result->Int32Value(ctx).FromJust());

  CHECK_GE(listener->num, 1);
}

TEST(AstExportKeyedLoad) {
  FLAG_taint_tracking_enable_export_ast = true;
  FLAG_taint_tracking_enable_ast_modification = true;
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  AstListener* listener = new AstListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var ret = 1;"
      "var tmp = [3, 1];"
      "tmp.forEach(function(val) {ret += val;});"
      "ret;");
  auto ctx = CcTest::isolate()->GetCurrentContext();
  auto result = v8::Script::Compile(ctx, source).ToLocalChecked()->Run();
  CHECK_EQ(5, result->Int32Value(ctx).FromJust());

  CHECK_GE(listener->num, 1);
}


TEST(AstExportWithModificationOptimize) {
  FLAG_taint_tracking_enable_export_ast = true;
  FLAG_taint_tracking_enable_ast_modification = true;
  FLAG_always_opt = true;
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  AstListener* listener = new AstListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var a = 'a'; "
      "var ret = 1; "
      "if (a == 'a') {"
      "  ret = 2;"
      "}"
      "var test_arr = [];"
      "test_arr = [1, 2];"
      "var ttt = {'asf': 1};"
      "for (var i = 0; i < 2; i++) {"
      "  ret += 1;"
      "}"
      "ret;");
  CHECK_LT(listener->num, 1);
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      4, result->Int32Value(
          CcTest::isolate()->GetCurrentContext()).FromJust());

  CHECK_GE(listener->num, 1);
}

TEST(AstExportIfNotOptimized) {
  FLAG_taint_tracking_enable_export_ast = true;
  FLAG_taint_tracking_enable_ast_modification = true;
  FLAG_always_opt = true;
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  AstListener* listener = new AstListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var ret;"
      "if (!ret) {"
      "  ret = {avar : 4};"
      "}"
      "if (!ret) {"
      "  ret = undefined;"
      "}"
      "ret.loadTimes = function() { return 1; };"
      "ret.csi = function(){ return this.avar; };"
      "ret.csi();");
  auto ctx = CcTest::isolate()->GetCurrentContext();
  auto result = v8::Script::Compile(ctx, source).ToLocalChecked()->Run();
  CHECK_EQ(4, result->Int32Value(ctx).FromJust());
}

TEST(AstExportMethodCallWithModificationOptimized) {
  FLAG_taint_tracking_enable_export_ast = true;
  FLAG_taint_tracking_enable_ast_modification = true;
  FLAG_always_opt = true;
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  AstListener* listener = new AstListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var ret = 1;"
      "var a = {addthree: function() {return this.three;}};"
      "a.three = 3;"
      "ret += a.addthree();"
      "ret;");
  auto ctx = CcTest::isolate()->GetCurrentContext();
  auto result = v8::Script::Compile(ctx, source).ToLocalChecked()->Run();
  CHECK_EQ(4, result->Int32Value(ctx).FromJust());

  CHECK_GE(listener->num, 1);
}

TEST(AstExportKeyedLoadOptimized) {
  FLAG_taint_tracking_enable_export_ast = true;
  FLAG_taint_tracking_enable_ast_modification = true;
  FLAG_always_opt = true;
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  AstListener* listener = new AstListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var ret = 1;"
      "var tmp = [3, 1];"
      "tmp.forEach(function(val) {ret += val;});"
      "ret;");
  auto ctx = CcTest::isolate()->GetCurrentContext();
  auto result = v8::Script::Compile(ctx, source).ToLocalChecked()->Run();
  CHECK_EQ(5, result->Int32Value(ctx).FromJust());

  CHECK_GE(listener->num, 1);
}


class ConcolicListener : public tainttracking::LogListener {
public:
  ConcolicListener() {}
  virtual ~ConcolicListener() {}
  virtual void OnLog(const ::TaintLogRecord::Reader& message) override {
    #define SC(V) static_cast<uint32_t>(V)

    if (message.getMessage().which() ==
        ::TaintLogRecord::Message::TAINTED_CONTROL_FLOW) {
      num += 1;
      #undef SC
    }
  }

  int num = 0;
};

void InitConcolicTestCase() {
  FLAG_taint_tracking_enable_export_ast = true;
  FLAG_taint_tracking_enable_ast_modification = true;
  FLAG_taint_tracking_enable_concolic = true;
  FLAG_ignition = false;
  FLAG_turbo = false;
  tainttracking::TaintTracker::FromIsolate(
          reinterpret_cast<v8::internal::Isolate*>(
              CcTest::isolate()))->Get()->Exec().Initialize();
}


TEST(ConcolicExec) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "if (tmp == 'safe') {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      2,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}


TEST(ConcolicExecIgnition) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "if (tmp == 'safe') {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      2,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicPropertyIgnition) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "if (tmp.length == 3) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      2,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicProperty) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "if (tmp.length == 3) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      2,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicFunctionPrototypeApply) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function callable(i, j, k) { return i + j + k; }"
      "if (3 == callable.apply(undefined, [tmp.length, 0, -1])) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicFunctionPrototypeCall) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function callable(i, j, k) { return i + j + k; }"
      "if (3 == callable.call(undefined, tmp.length, 0, -1)) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicPropertyCount) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "var tmp_len = [tmp.length];"
      "tmp_len[0]++;"
      "if (5 == tmp_len) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicVariableCount) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "var tmp_len = tmp.length;"
      "tmp_len++;"
      "if (5 == tmp_len) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicArrayLiteral) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var arr = ['other', tmp];"
      "var ret = 2;"
      "if (arr[arr.indexOf('asdf')].length == 4) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicArrayLiteralRuntime) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function run(){"
      "  var arr = ['other', tmp.length, [tmp.length, 'fine']];"
      "  if (arr[2][0] == 4) {"
      "    ret += 1;"
      "  }"
      "}"
      "run();"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicObjectLiteral) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function run(){"
      "  var arr = { 'key' : tmp.length };"
      "  if (arr['key'] == 4) {"
      "    ret += 1;"
      "  }"
      "}"
      "run();"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicObjectAssign) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function run() {"
      "  var arr = {};"
      "  arr['key'] = tmp.length;"
      "  if (arr['key'] == 4) {"
      "    ret += 1;"
      "  }"
      "}"
      "run();"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicThisReceiver) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "var obj = { "
      "  fn : function run() {"
      "    var arr = {};"
      "    if (this.key == 4) {"
      "      ret += 1;"
      "    }"
      "  }"
      "};"
      "obj.key = tmp.length;"
      "obj.fn();"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicObjectAssignSymbolicKey) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function run(){"
      "  var arr = {};"
      "  arr[tmp.length] = 1;"
      "  if (arr[4] == 1) {"
      "    ret += 1;"
      "  }"
      "}"
      "run();"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicArrayIndex) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function run() {"
      "  var arr = [tmp.length];"
      "  if (arr[0] == 4) {"
      "    ret += 1;"
      "  }"
      "}"
      "run();"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicApplyBuiltin) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function run(arr) {"
      "  if (arr == 4) {"
      "    ret += 1;"
      "  }"
      "}"
      "run.apply(undefined, [tmp.length]);"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicExceptionJsCaught) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function throwserr(arg) {"
      "  if (arg == 1) {"
      "    throw 'err';"
      "  } else {"
      "    return 0;"
      "  }"
      "}"
      "if (tmp.length == 4) {"
      "  try {"
      "    throwserr(1);"
      "    ret += 2;"
      "  } catch(e) {"
      "    ret += 1;"
      "  }"
      "}"
      "ret += throwserr(0);"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_EQ(
      1,
      tainttracking::TaintTracker::FromIsolate(
          reinterpret_cast<v8::internal::Isolate*>(
              CcTest::isolate()))->Get()->Exec().NumFrames());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicExceptionJsCatchArg) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function throwserr(arg) {"
      "  if (arg == 1) {"
      "    throw 'err';"
      "  } else {"
      "    return 0;"
      "  }"
      "}"
      "if (tmp.length == 4) {"
      "  try {"
      "    throwserr(throwserr(1));"
      "    ret += 2;"
      "  } catch(e) {"
      "    ret += 1;"
      "  }"
      "}"
      "ret += throwserr(0);"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_EQ(
      1,
      tainttracking::TaintTracker::FromIsolate(
          reinterpret_cast<v8::internal::Isolate*>(
              CcTest::isolate()))->Get()->Exec().NumFrames());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicExceptionJsRethrow) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function throwserr(arg) {"
      "  if (arg == 1) {"
      "    throw 'err';"
      "  } else {"
      "    return 0;"
      "  }"
      "}"
      "function catcheserr(arg) {"
      "  try {"
      "    throwserr(arg);"
      "  } catch(e) {"
      "    throw e;"
      "  }"
      "}"
      "if (tmp.length == 4) {"
      "  try {"
      "    catcheserr(1);"
      "    ret += 2;"
      "  } catch(e) {"
      "    ret += 1;"
      "  }"
      "}"
      "ret += throwserr(0);"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_EQ(
      1,
      tainttracking::TaintTracker::FromIsolate(
          reinterpret_cast<v8::internal::Isolate*>(
              CcTest::isolate()))->Get()->Exec().NumFrames());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicExceptionJsFinally) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "function throwserr(arg) {"
      "  try {"
      "    throw 'err';"
      "  } finally {"
      "    ret += 1;"
      "  }"
      "  return 0;"
      "}"
      "if (tmp.length == 4) {"
      "  try {"
      "    throwserr(1);"
      "  } catch(e) {"
      "    ret += 1;"
      "  }"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      4,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_EQ(
      1,
      tainttracking::TaintTracker::FromIsolate(
          reinterpret_cast<v8::internal::Isolate*>(
              CcTest::isolate()))->Get()->Exec().NumFrames());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}


TEST(ConcolicVariableStore) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "function func() {"
      "  var tmp = 'asdf';"
      "  tmp.__setTaint__(__taintConstants__().Url);"
      "  var store = tmp.length;"
      "  var ret = 2;"
      "  if (store == 3) {"
      "    ret += 1;"
      "  }"
      "  return ret;"
      "}"
      "func();");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      2,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_EQ(
      1,
      tainttracking::TaintTracker::FromIsolate(
          reinterpret_cast<v8::internal::Isolate*>(
              CcTest::isolate()))->Get()->Exec().NumFrames());
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicRecursion) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "function fib(n) {"
      "  if (n == 1 || n == 0) {"
      "    return 1;"
      "  }"
      "  var a = fib(n - 1);"
      "  var b = fib(n - 2);"
      "  return a + b;"
      "}"
      "fib(4);");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      5,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
}

TEST(ConcolicReturnValue) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "function make_tainted() {"
      "  var a = 'asdf';"
      "  a.__setTaint__(__taintConstants__().Url);"
      "  return a.length;"
      "}"
      "var ret = 4;"
      "if (ret == make_tainted()) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      5,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicShortcircuit) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "if (typeof (tmp.length) == 'number' || (ret = 10)) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicTypeof) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "if (typeof (tmp.length) == 'number') {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicAssignment) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 0;"
      "var l = 1;"
      "tmp = l = 2;"
      "tmp *= 2;"
      "l;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      2,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
}

TEST(ConcolicCall) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "if (tmp.charAt(ret) == 'd') {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

TEST(ConcolicCallIgnition) {
  TestCase test_case;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));
  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "if (tmp.charAt(ret) == 'd') {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3,
      result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  tainttracking::LogDispose(
      reinterpret_cast<v8::internal::Isolate*>(CcTest::isolate()));
  CHECK_GE(listener->num, 1);
}

static void concolic_api_test(const v8::FunctionCallbackInfo<v8::Value>& val) {
  val.GetReturnValue().Set(val[0]);
}

TEST(ConcolicApiFunction) {
  TestCase test_case;
  LocalContext env;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();

  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));

  v8::Local<v8::FunctionTemplate> foo_fun = v8::FunctionTemplate::New(
      CcTest::isolate(), concolic_api_test);

  CHECK(env->Global()->Set(env.local(),
                           v8_str("foo"),
                           foo_fun->GetFunction(env.local()).ToLocalChecked())
        .FromJust());

  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "if (tmp.length == foo(4)) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_GE(listener->num, 1);
}


static int concolic_accessor = 0;


static void concolic_accessor_test_getter(
    const v8::FunctionCallbackInfo<v8::Value>& val) {
  val.GetReturnValue().Set(concolic_accessor);
}

static void concolic_accessor_test_setter(
    const v8::FunctionCallbackInfo<v8::Value>& val) {
  concolic_accessor = val[0]->Int32Value(
      val.GetIsolate()->GetCurrentContext()).FromJust();
}


TEST(ConcolicApiAccessor) {
  concolic_accessor = 0;

  TestCase test_case;
  LocalContext env;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));

  v8::Local<v8::FunctionTemplate> foo_getter = v8::FunctionTemplate::New(
      CcTest::isolate(), concolic_accessor_test_getter);
  v8::Local<v8::FunctionTemplate> foo_setter = v8::FunctionTemplate::New(
      CcTest::isolate(), concolic_accessor_test_setter);

  v8::Local<v8::ObjectTemplate> bar_obj_template =
    v8::ObjectTemplate::New(CcTest::isolate());
  v8::Local<v8::Object> bar_obj =
    bar_obj_template->NewInstance(env.local()).ToLocalChecked();
  bar_obj->SetAccessorProperty(
      v8_str("barprop"),
      foo_getter->GetFunction(env.local()).ToLocalChecked(),
      foo_setter->GetFunction(env.local()).ToLocalChecked());

  CHECK(env->Global()->Set(env.local(),
                           v8_str("bar"),
                           bar_obj)
        .FromJust());

  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "ret += bar.barprop;"
      "bar.barprop = 4;"
      "if (tmp.length == bar.barprop) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_GE(listener->num, 1);
}


TEST(ConcolicKeyedApiAccessor) {
  concolic_accessor = 0;

  TestCase test_case;
  LocalContext env;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();

  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));

  v8::Local<v8::FunctionTemplate> foo_getter = v8::FunctionTemplate::New(
      CcTest::isolate(), concolic_accessor_test_getter);
  v8::Local<v8::FunctionTemplate> foo_setter = v8::FunctionTemplate::New(
      CcTest::isolate(), concolic_accessor_test_setter);

  v8::Local<v8::ObjectTemplate> bar_obj_template =
    v8::ObjectTemplate::New(CcTest::isolate());
  v8::Local<v8::Object> bar_obj =
    bar_obj_template->NewInstance(env.local()).ToLocalChecked();
  bar_obj->SetAccessorProperty(
      v8_str("barprop"),
      foo_getter->GetFunction(env.local()).ToLocalChecked(),
      foo_setter->GetFunction(env.local()).ToLocalChecked());

  CHECK(env->Global()->Set(env.local(),
                           v8_str("bar"),
                           bar_obj)
        .FromJust());

  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "ret += bar.barprop;"
      "bar.barprop = 4;"
      "if (tmp.length == bar['bar' + 'prop']) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_GE(listener->num, 1);
}


TEST(ConcolicApiAccessorTemplate) {
  concolic_accessor = 0;

  TestCase test_case;
  LocalContext env;
  v8::HandleScope scope(CcTest::isolate());
  InitConcolicTestCase();
  ConcolicListener* listener = new ConcolicListener();
  RegisterLogListener(std::unique_ptr<LogListener>(listener));

  v8::Local<v8::FunctionTemplate> foo_getter = v8::FunctionTemplate::New(
      CcTest::isolate(), concolic_accessor_test_getter);
  v8::Local<v8::FunctionTemplate> foo_setter = v8::FunctionTemplate::New(
      CcTest::isolate(), concolic_accessor_test_setter);

  v8::Local<v8::ObjectTemplate> bar_obj_template =
    v8::ObjectTemplate::New(CcTest::isolate());
  bar_obj_template->SetAccessorProperty(
      v8_str("barprop"),
      foo_getter,
      foo_setter);
  v8::Local<v8::Object> bar_obj =
    bar_obj_template->NewInstance(env.local()).ToLocalChecked();

  CHECK(env->Global()->Set(env.local(),
                           v8_str("bar"),
                           bar_obj)
        .FromJust());

  v8::Local<v8::String> source = v8_str(
      CcTest::isolate(),
      "var tmp = 'asdf';"
      "tmp.__setTaint__(__taintConstants__().Url);"
      "var ret = 2;"
      "ret += bar.barprop;"
      "bar.barprop = 4;"
      "if (tmp.length == bar.barprop) {"
      "  ret += 1;"
      "}"
      "ret;");
  auto result = v8::Script::Compile(
      CcTest::isolate()->GetCurrentContext(), source).ToLocalChecked()->Run();
  CHECK_EQ(
      3, result->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK_GE(listener->num, 1);
}
