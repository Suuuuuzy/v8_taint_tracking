// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins.h"
#include "src/builtins/builtins-utils.h"

#include "src/compiler.h"
#include "src/string-builder.h"

namespace v8 {
namespace internal {

namespace {

// ES6 section 19.2.1.1.1 CreateDynamicFunction
MaybeHandle<Object> CreateDynamicFunction(Isolate* isolate,
                                          BuiltinArguments args,
                                          const char* token) {
  // Compute number of arguments, ignoring the receiver.
  DCHECK_LE(1, args.length());
  int const argc = args.length() - 1;

  Handle<JSFunction> target = args.target<JSFunction>();
  Handle<JSObject> target_global_proxy(target->global_proxy(), isolate);

  if (!Builtins::AllowDynamicFunction(isolate, target, target_global_proxy)) {
    isolate->CountUsage(v8::Isolate::kFunctionConstructorReturnedUndefined);
    return isolate->factory()->undefined_value();
  }

  // Build the source string.
  Handle<String> source;
  {
    IncrementalStringBuilder builder(isolate);
    builder.AppendCharacter('(');
    builder.AppendCString(token);
    builder.AppendCharacter('(');
    bool parenthesis_in_arg_string = false;
    if (argc > 1) {
      for (int i = 1; i < argc; ++i) {
        if (i > 1) builder.AppendCharacter(',');
        Handle<String> param;
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate, param, Object::ToString(isolate, args.at<Object>(i)),
            Object);
        param = String::Flatten(param);

        tainttracking::LogIfTainted(Handle<String>::cast(param),
                                    tainttracking::TaintSinkLabel::JAVASCRIPT,
                                    i - 1);

        builder.AppendString(param);
        // If the formal parameters string include ) - an illegal
        // character - it may make the combined function expression
        // compile. We avoid this problem by checking for this early on.
        DisallowHeapAllocation no_gc;  // Ensure vectors stay valid.
        String::FlatContent param_content = param->GetFlatContent();
        for (int i = 0, length = param->length(); i < length; ++i) {
          if (param_content.Get(i) == ')') {
            parenthesis_in_arg_string = true;
            break;
          }
        }
      }
      // If the formal parameters include an unbalanced block comment, the
      // function must be rejected. Since JavaScript does not allow nested
      // comments we can include a trailing block comment to catch this.
      builder.AppendCString("\n/**/");
    }
    builder.AppendCString(") {\n");
    if (argc > 0) {
      Handle<String> body;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, body, Object::ToString(isolate, args.at<Object>(argc)),
          Object);

      tainttracking::LogIfTainted(Handle<String>::cast(body),
                                  tainttracking::TaintSinkLabel::JAVASCRIPT,
                                  argc - 1);

      builder.AppendString(body);
    }
    builder.AppendCString("\n})");
    ASSIGN_RETURN_ON_EXCEPTION(isolate, source, builder.Finish(), Object);

    // The SyntaxError must be thrown after all the (observable) ToString
    // conversions are done.
    if (parenthesis_in_arg_string) {
      THROW_NEW_ERROR(isolate,
                      NewSyntaxError(MessageTemplate::kParenthesisInArgString),
                      Object);
    }
  }

  // Compile the string in the constructor and not a helper so that errors to
  // come from here.
  Handle<JSFunction> function;
  {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, function,
                               Compiler::GetFunctionFromString(
                                   handle(target->native_context(), isolate),
                                   source, ONLY_SINGLE_FUNCTION_LITERAL),
                               Object);
    Handle<Object> result;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, result,
        Execution::Call(isolate, function, target_global_proxy, 0, nullptr),
        Object);
    function = Handle<JSFunction>::cast(result);
    function->shared()->set_name_should_print_as_anonymous(true);
  }

  // If new.target is equal to target then the function created
  // is already correctly setup and nothing else should be done
  // here. But if new.target is not equal to target then we are
  // have a Function builtin subclassing case and therefore the
  // function has wrong initial map. To fix that we create a new
  // function object with correct initial map.
  Handle<Object> unchecked_new_target = args.new_target();
  if (!unchecked_new_target->IsUndefined(isolate) &&
      !unchecked_new_target.is_identical_to(target)) {
    Handle<JSReceiver> new_target =
        Handle<JSReceiver>::cast(unchecked_new_target);
    Handle<Map> initial_map;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, initial_map,
        JSFunction::GetDerivedMap(isolate, target, new_target), Object);

    Handle<SharedFunctionInfo> shared_info(function->shared(), isolate);
    Handle<Map> map = Map::AsLanguageMode(
        initial_map, shared_info->language_mode(), shared_info->kind());

    Handle<Context> context(function->context(), isolate);
    function = isolate->factory()->NewFunctionFromSharedFunctionInfo(
        map, shared_info, context, NOT_TENURED);
  }
  return function;
}

}  // namespace

// ES6 section 19.2.1.1 Function ( p1, p2, ... , pn, body )
BUILTIN(FunctionConstructor) {
  HandleScope scope(isolate);
  Handle<Object> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, result, CreateDynamicFunction(isolate, args, "function"));
  return *result;
}

// ES6 section 25.2.1.1 GeneratorFunction (p1, p2, ... , pn, body)
BUILTIN(GeneratorFunctionConstructor) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(isolate,
                           CreateDynamicFunction(isolate, args, "function*"));
}

BUILTIN(AsyncFunctionConstructor) {
  HandleScope scope(isolate);
  Handle<Object> maybe_func;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, maybe_func,
      CreateDynamicFunction(isolate, args, "async function"));
  if (!maybe_func->IsJSFunction()) return *maybe_func;

  // Do not lazily compute eval position for AsyncFunction, as they may not be
  // determined after the function is resumed.
  Handle<JSFunction> func = Handle<JSFunction>::cast(maybe_func);
  Handle<Script> script = handle(Script::cast(func->shared()->script()));
  int position = script->GetEvalPosition();
  USE(position);

  return *func;
}

namespace {

Object* DoFunctionBind(Isolate* isolate, BuiltinArguments args) {
  HandleScope scope(isolate);
  DCHECK_LE(1, args.length());
  if (!args.receiver()->IsCallable()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kFunctionBind));
  }

  // Allocate the bound function with the given {this_arg} and {args}.
  Handle<JSReceiver> target = args.at<JSReceiver>(0);
  Handle<Object> this_arg = isolate->factory()->undefined_value();
  ScopedVector<Handle<Object>> argv(std::max(0, args.length() - 2));
  if (args.length() > 1) {
    this_arg = args.at<Object>(1);
    for (int i = 2; i < args.length(); ++i) {
      argv[i - 2] = args.at<Object>(i);
    }
  }
  Handle<JSBoundFunction> function;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, function,
      isolate->factory()->NewJSBoundFunction(target, this_arg, argv));

  LookupIterator length_lookup(target, isolate->factory()->length_string(),
                               target, LookupIterator::OWN);
  // Setup the "length" property based on the "length" of the {target}.
  // If the targets length is the default JSFunction accessor, we can keep the
  // accessor that's installed by default on the JSBoundFunction. It lazily
  // computes the value from the underlying internal length.
  if (!target->IsJSFunction() ||
      length_lookup.state() != LookupIterator::ACCESSOR ||
      !length_lookup.GetAccessors()->IsAccessorInfo()) {
    Handle<Object> length(Smi::FromInt(0), isolate);
    Maybe<PropertyAttributes> attributes =
        JSReceiver::GetPropertyAttributes(&length_lookup);
    if (!attributes.IsJust()) return isolate->heap()->exception();
    if (attributes.FromJust() != ABSENT) {
      Handle<Object> target_length;
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, target_length,
                                         Object::GetProperty(&length_lookup));
      if (target_length->IsNumber()) {
        length = isolate->factory()->NewNumber(std::max(
            0.0, DoubleToInteger(target_length->Number()) - argv.length()));
      }
    }
    LookupIterator it(function, isolate->factory()->length_string(), function);
    DCHECK_EQ(LookupIterator::ACCESSOR, it.state());
    RETURN_FAILURE_ON_EXCEPTION(isolate,
                                JSObject::DefineOwnPropertyIgnoreAttributes(
                                    &it, length, it.property_attributes()));
  }

  // Setup the "name" property based on the "name" of the {target}.
  // If the targets name is the default JSFunction accessor, we can keep the
  // accessor that's installed by default on the JSBoundFunction. It lazily
  // computes the value from the underlying internal name.
  LookupIterator name_lookup(target, isolate->factory()->name_string(), target,
                             LookupIterator::OWN);
  if (!target->IsJSFunction() ||
      name_lookup.state() != LookupIterator::ACCESSOR ||
      !name_lookup.GetAccessors()->IsAccessorInfo()) {
    Handle<Object> target_name;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, target_name,
                                       Object::GetProperty(&name_lookup));
    Handle<String> name;
    if (target_name->IsString()) {
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
          isolate, name,
          Name::ToFunctionName(Handle<String>::cast(target_name)));
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
          isolate, name, isolate->factory()->NewConsString(
                             isolate->factory()->bound__string(), name));
    } else {
      name = isolate->factory()->bound__string();
    }
    LookupIterator it(function, isolate->factory()->name_string());
    DCHECK_EQ(LookupIterator::ACCESSOR, it.state());
    RETURN_FAILURE_ON_EXCEPTION(isolate,
                                JSObject::DefineOwnPropertyIgnoreAttributes(
                                    &it, name, it.property_attributes()));
  }
  return *function;
}

}  // namespace

// ES6 section 19.2.3.2 Function.prototype.bind ( thisArg, ...args )
BUILTIN(FunctionPrototypeBind) { return DoFunctionBind(isolate, args); }

// TODO(verwaest): This is a temporary helper until the FastFunctionBind stub
// can tailcall to the builtin directly.
RUNTIME_FUNCTION(Runtime_FunctionBind) {
  DCHECK_EQ(2, args.length());
  Arguments* incoming = reinterpret_cast<Arguments*>(args[0]);
  // Rewrap the arguments as builtins arguments.
  int argc = incoming->length() + BuiltinArguments::kNumExtraArgsWithReceiver;
  BuiltinArguments caller_args(argc, incoming->arguments() + 1);
  return DoFunctionBind(isolate, caller_args);
}

// ES6 section 19.2.3.5 Function.prototype.toString ( )
BUILTIN(FunctionPrototypeToString) {
  HandleScope scope(isolate);
  Handle<Object> receiver = args.receiver();
  if (receiver->IsJSBoundFunction()) {
    return *JSBoundFunction::ToString(Handle<JSBoundFunction>::cast(receiver));
  } else if (receiver->IsJSFunction()) {
    return *JSFunction::ToString(Handle<JSFunction>::cast(receiver));
  }
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kNotGeneric,
                            isolate->factory()->NewStringFromAsciiChecked(
                                "Function.prototype.toString")));
}

// ES6 section 19.2.3.6 Function.prototype [ @@hasInstance ] ( V )
void Builtins::Generate_FunctionPrototypeHasInstance(
    CodeStubAssembler* assembler) {
  using compiler::Node;

  Node* f = assembler->Parameter(0);
  Node* v = assembler->Parameter(1);
  Node* context = assembler->Parameter(4);
  Node* result = assembler->OrdinaryHasInstance(context, f, v);
  assembler->Return(result);
}

}  // namespace internal
}  // namespace v8
