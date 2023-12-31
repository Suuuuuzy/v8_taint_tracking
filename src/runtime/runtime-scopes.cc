// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/runtime/runtime-utils.h"

#include <memory>

#include "src/accessors.h"
#include "src/arguments.h"
#include "src/ast/scopes.h"
#include "src/deoptimizer.h"
#include "src/frames-inl.h"
#include "src/isolate-inl.h"
#include "src/messages.h"

namespace v8 {
namespace internal {

RUNTIME_FUNCTION(Runtime_ThrowConstAssignError) {
  HandleScope scope(isolate);
  THROW_NEW_ERROR_RETURN_FAILURE(isolate,
                                 NewTypeError(MessageTemplate::kConstAssign));
}

namespace {

enum class RedeclarationType { kSyntaxError = 0, kTypeError = 1 };

Object* ThrowRedeclarationError(Isolate* isolate, Handle<String> name,
                                RedeclarationType redeclaration_type) {
  HandleScope scope(isolate);
  if (redeclaration_type == RedeclarationType::kSyntaxError) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewSyntaxError(MessageTemplate::kVarRedeclaration, name));
  } else {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kVarRedeclaration, name));
  }
}


// May throw a RedeclarationError.
Object* DeclareGlobal(
    Isolate* isolate, Handle<JSGlobalObject> global, Handle<String> name,
    Handle<Object> value, PropertyAttributes attr, bool is_var,
    bool is_function, RedeclarationType redeclaration_type,
    Handle<TypeFeedbackVector> feedback_vector = Handle<TypeFeedbackVector>(),
    FeedbackVectorSlot slot = FeedbackVectorSlot::Invalid()) {
  Handle<ScriptContextTable> script_contexts(
      global->native_context()->script_context_table());
  ScriptContextTable::LookupResult lookup;
  if (ScriptContextTable::Lookup(script_contexts, name, &lookup) &&
      IsLexicalVariableMode(lookup.mode)) {
    // ES#sec-globaldeclarationinstantiation 6.a:
    // If envRec.HasLexicalDeclaration(name) is true, throw a SyntaxError
    // exception.
    return ThrowRedeclarationError(isolate, name,
                                   RedeclarationType::kSyntaxError);
  }

  // Do the lookup own properties only, see ES5 erratum.
  LookupIterator it(global, name, global, LookupIterator::OWN_SKIP_INTERCEPTOR);
  Maybe<PropertyAttributes> maybe = JSReceiver::GetPropertyAttributes(&it);
  if (!maybe.IsJust()) return isolate->heap()->exception();

  if (it.IsFound()) {
    PropertyAttributes old_attributes = maybe.FromJust();
    // The name was declared before; check for conflicting re-declarations.

    // Skip var re-declarations.
    if (is_var) return isolate->heap()->undefined_value();

    DCHECK(is_function);
    if ((old_attributes & DONT_DELETE) != 0) {
      // Only allow reconfiguring globals to functions in user code (no
      // natives, which are marked as read-only).
      DCHECK((attr & READ_ONLY) == 0);

      // Check whether we can reconfigure the existing property into a
      // function.
      PropertyDetails old_details = it.property_details();
      if (old_details.IsReadOnly() || old_details.IsDontEnum() ||
          (it.state() == LookupIterator::ACCESSOR &&
           it.GetAccessors()->IsAccessorPair())) {
        // ES#sec-globaldeclarationinstantiation 5.d:
        // If hasRestrictedGlobal is true, throw a SyntaxError exception.
        // ES#sec-evaldeclarationinstantiation 8.a.iv.1.b:
        // If fnDefinable is false, throw a TypeError exception.
        return ThrowRedeclarationError(isolate, name, redeclaration_type);
      }
      // If the existing property is not configurable, keep its attributes. Do
      attr = old_attributes;
    }

    // If the current state is ACCESSOR, this could mean it's an AccessorInfo
    // type property. We are not allowed to call into such setters during global
    // function declaration since this would break e.g., onload. Meaning
    // 'function onload() {}' would invalidly register that function as the
    // onload callback. To avoid this situation, we first delete the property
    // before readding it as a regular data property below.
    if (it.state() == LookupIterator::ACCESSOR) it.Delete();
  }

  // Define or redefine own property.
  RETURN_FAILURE_ON_EXCEPTION(
      isolate, JSObject::DefineOwnPropertyIgnoreAttributes(&it, value, attr));

  if (!feedback_vector.is_null()) {
    DCHECK_EQ(*global, *it.GetHolder<Object>());
    // Preinitialize the feedback slot if the global object does not have
    // named interceptor or the interceptor is not masking.
    if (!global->HasNamedInterceptor() ||
        global->GetNamedInterceptor()->non_masking()) {
      LoadGlobalICNexus nexus(feedback_vector, slot);
      nexus.ConfigurePropertyCellMode(it.GetPropertyCell());
    }
  }
  return isolate->heap()->undefined_value();
}

Object* DeclareGlobals(Isolate* isolate, Handle<FixedArray> pairs, int flags,
                       Handle<TypeFeedbackVector> feedback_vector) {
  HandleScope scope(isolate);
  Handle<JSGlobalObject> global(isolate->global_object());
  Handle<Context> context(isolate->context());

  // Traverse the name/value pairs and set the properties.
  int length = pairs->length();
  FOR_WITH_HANDLE_SCOPE(isolate, int, i = 0, i, i < length, i += 2, {
    FeedbackVectorSlot slot(Smi::cast(pairs->get(i))->value());
    Handle<String> name(feedback_vector->GetName(slot), isolate);
    Handle<Object> initial_value(pairs->get(i + 1), isolate);

    bool is_var = initial_value->IsUndefined(isolate);
    bool is_function = initial_value->IsSharedFunctionInfo();
    DCHECK_EQ(1, BoolToInt(is_var) + BoolToInt(is_function));

    Handle<Object> value;
    if (is_function) {
      // Copy the function and update its context. Use it as value.
      Handle<SharedFunctionInfo> shared =
          Handle<SharedFunctionInfo>::cast(initial_value);
      Handle<JSFunction> function =
          isolate->factory()->NewFunctionFromSharedFunctionInfo(shared, context,
                                                                TENURED);
      value = function;
    } else {
      value = isolate->factory()->undefined_value();
    }

    // Compute the property attributes. According to ECMA-262,
    // the property must be non-configurable except in eval.
    bool is_native = DeclareGlobalsNativeFlag::decode(flags);
    bool is_eval = DeclareGlobalsEvalFlag::decode(flags);
    int attr = NONE;
    if (is_function && is_native) attr |= READ_ONLY;
    if (!is_eval) attr |= DONT_DELETE;

    // ES#sec-globaldeclarationinstantiation 5.d:
    // If hasRestrictedGlobal is true, throw a SyntaxError exception.
    Object* result = DeclareGlobal(
        isolate, global, name, value, static_cast<PropertyAttributes>(attr),
        is_var, is_function, RedeclarationType::kSyntaxError, feedback_vector,
        slot);
    if (isolate->has_pending_exception()) return result;
  });

  return isolate->heap()->undefined_value();
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DeclareGlobals) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  CONVERT_ARG_HANDLE_CHECKED(FixedArray, pairs, 0);
  CONVERT_SMI_ARG_CHECKED(flags, 1);
  CONVERT_ARG_HANDLE_CHECKED(TypeFeedbackVector, feedback_vector, 2);

  return DeclareGlobals(isolate, pairs, flags, feedback_vector);
}

// TODO(ishell): merge this with Runtime::kDeclareGlobals once interpreter
// is able to pass feedback vector.
RUNTIME_FUNCTION(Runtime_DeclareGlobalsForInterpreter) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  CONVERT_ARG_HANDLE_CHECKED(FixedArray, pairs, 0);
  CONVERT_SMI_ARG_CHECKED(flags, 1);
  CONVERT_ARG_HANDLE_CHECKED(JSFunction, closure, 2);

  Handle<TypeFeedbackVector> feedback_vector(closure->feedback_vector(),
                                             isolate);
  return DeclareGlobals(isolate, pairs, flags, feedback_vector);
}

RUNTIME_FUNCTION(Runtime_InitializeVarGlobal) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  CONVERT_ARG_HANDLE_CHECKED(String, name, 0);
  CONVERT_LANGUAGE_MODE_ARG_CHECKED(language_mode, 1);
  CONVERT_ARG_HANDLE_CHECKED(Object, value, 2);

  Handle<JSGlobalObject> global(isolate->global_object());
  RETURN_RESULT_OR_FAILURE(
      isolate, Object::SetProperty(global, name, value, language_mode));
}


RUNTIME_FUNCTION(Runtime_InitializeConstGlobal) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(2, args.length());
  CONVERT_ARG_HANDLE_CHECKED(String, name, 0);
  CONVERT_ARG_HANDLE_CHECKED(Object, value, 1);

  Handle<JSGlobalObject> global(isolate->global_object());

  // Lookup the property as own on the global object.
  LookupIterator it(global, name, global, LookupIterator::OWN_SKIP_INTERCEPTOR);
  Maybe<PropertyAttributes> maybe = JSReceiver::GetPropertyAttributes(&it);
  DCHECK(maybe.IsJust());
  PropertyAttributes old_attributes = maybe.FromJust();

  PropertyAttributes attr =
      static_cast<PropertyAttributes>(DONT_DELETE | READ_ONLY);
  // Set the value if the property is either missing, or the property attributes
  // allow setting the value without invoking an accessor.
  if (it.IsFound()) {
    // Ignore if we can't reconfigure the value.
    if ((old_attributes & DONT_DELETE) != 0) {
      if ((old_attributes & READ_ONLY) != 0 ||
          it.state() == LookupIterator::ACCESSOR) {
        return *value;
      }
      attr = static_cast<PropertyAttributes>(old_attributes | READ_ONLY);
    }
  }

  RETURN_FAILURE_ON_EXCEPTION(
      isolate, JSObject::DefineOwnPropertyIgnoreAttributes(&it, value, attr));

  return *value;
}

namespace {

Object* DeclareEvalHelper(Isolate* isolate, Handle<String> name,
                          Handle<Object> value) {
  // Declarations are always made in a function, native, or script context, or
  // a declaration block scope. Since this is called from eval, the context
  // passed is the context of the caller, which may be some nested context and
  // not the declaration context.
  Handle<Context> context_arg(isolate->context(), isolate);
  Handle<Context> context(context_arg->declaration_context(), isolate);

  DCHECK(context->IsFunctionContext() || context->IsNativeContext() ||
         context->IsScriptContext() ||
         (context->IsBlockContext() && context->has_extension()));

  bool is_function = value->IsJSFunction();
  bool is_var = !is_function;
  DCHECK(!is_var || value->IsUndefined(isolate));

  int index;
  PropertyAttributes attributes;
  InitializationFlag init_flag;
  VariableMode mode;

  // Check for a conflict with a lexically scoped variable
  context_arg->Lookup(name, LEXICAL_TEST, &index, &attributes, &init_flag,
                      &mode);
  if (attributes != ABSENT && IsLexicalVariableMode(mode)) {
    // ES#sec-evaldeclarationinstantiation 5.a.i.1:
    // If varEnvRec.HasLexicalDeclaration(name) is true, throw a SyntaxError
    // exception.
    // ES#sec-evaldeclarationinstantiation 5.d.ii.2.a.i:
    // Throw a SyntaxError exception.
    return ThrowRedeclarationError(isolate, name,
                                   RedeclarationType::kSyntaxError);
  }

  Handle<Object> holder = context->Lookup(name, DONT_FOLLOW_CHAINS, &index,
                                          &attributes, &init_flag, &mode);
  DCHECK(!isolate->has_pending_exception());

  Handle<JSObject> object;

  if (attributes != ABSENT && holder->IsJSGlobalObject()) {
    // ES#sec-evaldeclarationinstantiation 8.a.iv.1.b:
    // If fnDefinable is false, throw a TypeError exception.
    return DeclareGlobal(isolate, Handle<JSGlobalObject>::cast(holder), name,
                         value, NONE, is_var, is_function,
                         RedeclarationType::kTypeError);
  }
  if (context_arg->extension()->IsJSGlobalObject()) {
    Handle<JSGlobalObject> global(
        JSGlobalObject::cast(context_arg->extension()), isolate);
    return DeclareGlobal(isolate, global, name, value, NONE, is_var,
                         is_function, RedeclarationType::kTypeError);
  } else if (context->IsScriptContext()) {
    DCHECK(context->global_object()->IsJSGlobalObject());
    Handle<JSGlobalObject> global(
        JSGlobalObject::cast(context->global_object()), isolate);
    return DeclareGlobal(isolate, global, name, value, NONE, is_var,
                         is_function, RedeclarationType::kTypeError);
  }

  if (attributes != ABSENT) {
    DCHECK_EQ(NONE, attributes);

    // Skip var re-declarations.
    if (is_var) return isolate->heap()->undefined_value();

    DCHECK(is_function);
    if (index != Context::kNotFound) {
      DCHECK(holder.is_identical_to(context));
      context->set(index, *value);
      return isolate->heap()->undefined_value();
    }

    object = Handle<JSObject>::cast(holder);

  } else if (context->has_extension()) {
    // Sloppy varblock contexts might not have an extension object yet,
    // in which case their extension is a ScopeInfo.
    if (context->extension()->IsScopeInfo()) {
      DCHECK(context->IsBlockContext());
      object = isolate->factory()->NewJSObject(
          isolate->context_extension_function());
      Handle<HeapObject> extension =
          isolate->factory()->NewSloppyBlockWithEvalContextExtension(
              handle(context->scope_info()), object);
      context->set_extension(*extension);
    } else {
      object = handle(context->extension_object(), isolate);
    }
    DCHECK(object->IsJSContextExtensionObject() || object->IsJSGlobalObject());
  } else {
    DCHECK(context->IsFunctionContext());
    object =
        isolate->factory()->NewJSObject(isolate->context_extension_function());
    context->set_extension(*object);
  }

  RETURN_FAILURE_ON_EXCEPTION(isolate, JSObject::SetOwnPropertyIgnoreAttributes(
                                           object, name, value, NONE));

  return isolate->heap()->undefined_value();
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DeclareEvalFunction) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  CONVERT_ARG_HANDLE_CHECKED(String, name, 0);
  CONVERT_ARG_HANDLE_CHECKED(Object, value, 1);
  return DeclareEvalHelper(isolate, name, value);
}

RUNTIME_FUNCTION(Runtime_DeclareEvalVar) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  CONVERT_ARG_HANDLE_CHECKED(String, name, 0);
  return DeclareEvalHelper(isolate, name,
                           isolate->factory()->undefined_value());
}

namespace {

// Find the arguments of the JavaScript function invocation that called
// into C++ code. Collect these in a newly allocated array of handles.
std::unique_ptr<Handle<Object>[]> GetCallerArguments(Isolate* isolate,
                                                     int* total_argc) {
  // Find frame containing arguments passed to the caller.
  JavaScriptFrameIterator it(isolate);
  JavaScriptFrame* frame = it.frame();
  List<JSFunction*> functions(2);
  frame->GetFunctions(&functions);
  if (functions.length() > 1) {
    int inlined_jsframe_index = functions.length() - 1;
    TranslatedState translated_values(frame);
    translated_values.Prepare(false, frame->fp());

    int argument_count = 0;
    TranslatedFrame* translated_frame =
        translated_values.GetArgumentsInfoFromJSFrameIndex(
            inlined_jsframe_index, &argument_count);
    TranslatedFrame::iterator iter = translated_frame->begin();

    // Skip the function.
    iter++;

    // Skip the receiver.
    iter++;
    argument_count--;

    *total_argc = argument_count;
    std::unique_ptr<Handle<Object>[]> param_data(
        NewArray<Handle<Object>>(*total_argc));
    bool should_deoptimize = false;
    for (int i = 0; i < argument_count; i++) {
      should_deoptimize = should_deoptimize || iter->IsMaterializedObject();
      Handle<Object> value = iter->GetValue();
      param_data[i] = value;
      iter++;
    }

    if (should_deoptimize) {
      translated_values.StoreMaterializedValuesAndDeopt();
    }

    return param_data;
  } else {
    it.AdvanceToArgumentsFrame();
    frame = it.frame();
    int args_count = frame->ComputeParametersCount();

    *total_argc = args_count;
    std::unique_ptr<Handle<Object>[]> param_data(
        NewArray<Handle<Object>>(*total_argc));
    for (int i = 0; i < args_count; i++) {
      Handle<Object> val = Handle<Object>(frame->GetParameter(i), isolate);
      param_data[i] = val;
    }
    return param_data;
  }
}

template <typename T>
Handle<JSObject> NewSloppyArguments(Isolate* isolate, Handle<JSFunction> callee,
                                    T parameters, int argument_count) {
  CHECK(!IsSubclassConstructor(callee->shared()->kind()));
  DCHECK(callee->shared()->has_simple_parameters());
  Handle<JSObject> result =
      isolate->factory()->NewArgumentsObject(callee, argument_count);

  // Allocate the elements if needed.
  int parameter_count = callee->shared()->internal_formal_parameter_count();
  if (argument_count > 0) {
    if (parameter_count > 0) {
      int mapped_count = Min(argument_count, parameter_count);
      Handle<FixedArray> parameter_map =
          isolate->factory()->NewFixedArray(mapped_count + 2, NOT_TENURED);
      parameter_map->set_map(isolate->heap()->sloppy_arguments_elements_map());
      result->set_map(isolate->native_context()->fast_aliased_arguments_map());
      result->set_elements(*parameter_map);

      // Store the context and the arguments array at the beginning of the
      // parameter map.
      Handle<Context> context(isolate->context());
      Handle<FixedArray> arguments =
          isolate->factory()->NewFixedArray(argument_count, NOT_TENURED);
      parameter_map->set(0, *context);
      parameter_map->set(1, *arguments);

      // Loop over the actual parameters backwards.
      int index = argument_count - 1;
      while (index >= mapped_count) {
        // These go directly in the arguments array and have no
        // corresponding slot in the parameter map.
        arguments->set(index, parameters[index]);
        --index;
      }

      Handle<ScopeInfo> scope_info(callee->shared()->scope_info());
      while (index >= 0) {
        // Detect duplicate names to the right in the parameter list.
        Handle<String> name(scope_info->ParameterName(index));
        int context_local_count = scope_info->ContextLocalCount();
        bool duplicate = false;
        for (int j = index + 1; j < parameter_count; ++j) {
          if (scope_info->ParameterName(j) == *name) {
            duplicate = true;
            break;
          }
        }

        if (duplicate) {
          // This goes directly in the arguments array with a hole in the
          // parameter map.
          arguments->set(index, parameters[index]);
          parameter_map->set_the_hole(index + 2);
        } else {
          // The context index goes in the parameter map with a hole in the
          // arguments array.
          int context_index = -1;
          for (int j = 0; j < context_local_count; ++j) {
            if (scope_info->ContextLocalName(j) == *name) {
              context_index = j;
              break;
            }
          }

          DCHECK(context_index >= 0);
          arguments->set_the_hole(index);
          parameter_map->set(
              index + 2,
              Smi::FromInt(Context::MIN_CONTEXT_SLOTS + context_index));
        }

        --index;
      }
    } else {
      // If there is no aliasing, the arguments object elements are not
      // special in any way.
      Handle<FixedArray> elements =
          isolate->factory()->NewFixedArray(argument_count, NOT_TENURED);
      result->set_elements(*elements);
      for (int i = 0; i < argument_count; ++i) {
        elements->set(i, parameters[i]);
      }
    }
  }
  return result;
}


class HandleArguments BASE_EMBEDDED {
 public:
  explicit HandleArguments(Handle<Object>* array) : array_(array) {}
  Object* operator[](int index) { return *array_[index]; }

 private:
  Handle<Object>* array_;
};


class ParameterArguments BASE_EMBEDDED {
 public:
  explicit ParameterArguments(Object** parameters) : parameters_(parameters) {}
  Object*& operator[](int index) { return *(parameters_ - index - 1); }

 private:
  Object** parameters_;
};

}  // namespace


RUNTIME_FUNCTION(Runtime_NewSloppyArguments_Generic) {
  HandleScope scope(isolate);
  DCHECK(args.length() == 1);
  CONVERT_ARG_HANDLE_CHECKED(JSFunction, callee, 0);
  // This generic runtime function can also be used when the caller has been
  // inlined, we use the slow but accurate {GetCallerArguments}.
  int argument_count = 0;
  std::unique_ptr<Handle<Object>[]> arguments =
      GetCallerArguments(isolate, &argument_count);
  HandleArguments argument_getter(arguments.get());
  return *NewSloppyArguments(isolate, callee, argument_getter, argument_count);
}


RUNTIME_FUNCTION(Runtime_NewStrictArguments) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  CONVERT_ARG_HANDLE_CHECKED(JSFunction, callee, 0);
  // This generic runtime function can also be used when the caller has been
  // inlined, we use the slow but accurate {GetCallerArguments}.
  int argument_count = 0;
  std::unique_ptr<Handle<Object>[]> arguments =
      GetCallerArguments(isolate, &argument_count);
  Handle<JSObject> result =
      isolate->factory()->NewArgumentsObject(callee, argument_count);
  if (argument_count) {
    Handle<FixedArray> array =
        isolate->factory()->NewUninitializedFixedArray(argument_count);
    DisallowHeapAllocation no_gc;
    WriteBarrierMode mode = array->GetWriteBarrierMode(no_gc);
    for (int i = 0; i < argument_count; i++) {
      array->set(i, *arguments[i], mode);
    }
    result->set_elements(*array);
  }
  return *result;
}


RUNTIME_FUNCTION(Runtime_NewRestParameter) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  CONVERT_ARG_HANDLE_CHECKED(JSFunction, callee, 0)
  int start_index = callee->shared()->internal_formal_parameter_count();
  // This generic runtime function can also be used when the caller has been
  // inlined, we use the slow but accurate {GetCallerArguments}.
  int argument_count = 0;
  std::unique_ptr<Handle<Object>[]> arguments =
      GetCallerArguments(isolate, &argument_count);
  int num_elements = std::max(0, argument_count - start_index);
  Handle<JSObject> result =
      isolate->factory()->NewJSArray(FAST_ELEMENTS, num_elements, num_elements,
                                     DONT_INITIALIZE_ARRAY_ELEMENTS);
  {
    DisallowHeapAllocation no_gc;
    FixedArray* elements = FixedArray::cast(result->elements());
    WriteBarrierMode mode = elements->GetWriteBarrierMode(no_gc);
    for (int i = 0; i < num_elements; i++) {
      elements->set(i, *arguments[i + start_index], mode);
    }
  }
  return *result;
}


RUNTIME_FUNCTION(Runtime_NewSloppyArguments) {
  HandleScope scope(isolate);
  DCHECK(args.length() == 3);
  CONVERT_ARG_HANDLE_CHECKED(JSFunction, callee, 0);
  Object** parameters = reinterpret_cast<Object**>(args[1]);
  CONVERT_SMI_ARG_CHECKED(argument_count, 2);
  ParameterArguments argument_getter(parameters);
  return *NewSloppyArguments(isolate, callee, argument_getter, argument_count);
}


RUNTIME_FUNCTION(Runtime_NewClosure) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  CONVERT_ARG_HANDLE_CHECKED(SharedFunctionInfo, shared, 0);
  Handle<Context> context(isolate->context(), isolate);
  return *isolate->factory()->NewFunctionFromSharedFunctionInfo(shared, context,
                                                                NOT_TENURED);
}


RUNTIME_FUNCTION(Runtime_NewClosure_Tenured) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  CONVERT_ARG_HANDLE_CHECKED(SharedFunctionInfo, shared, 0);
  Handle<Context> context(isolate->context(), isolate);
  // The caller ensures that we pretenure closures that are assigned
  // directly to properties.
  return *isolate->factory()->NewFunctionFromSharedFunctionInfo(shared, context,
                                                                TENURED);
}

static Object* FindNameClash(Handle<ScopeInfo> scope_info,
                             Handle<JSGlobalObject> global_object,
                             Handle<ScriptContextTable> script_context) {
  Isolate* isolate = scope_info->GetIsolate();
  for (int var = 0; var < scope_info->ContextLocalCount(); var++) {
    Handle<String> name(scope_info->ContextLocalName(var));
    VariableMode mode = scope_info->ContextLocalMode(var);
    ScriptContextTable::LookupResult lookup;
    if (ScriptContextTable::Lookup(script_context, name, &lookup)) {
      if (IsLexicalVariableMode(mode) || IsLexicalVariableMode(lookup.mode)) {
        // ES#sec-globaldeclarationinstantiation 5.b:
        // If envRec.HasLexicalDeclaration(name) is true, throw a SyntaxError
        // exception.
        return ThrowRedeclarationError(isolate, name,
                                       RedeclarationType::kSyntaxError);
      }
    }

    if (IsLexicalVariableMode(mode)) {
      LookupIterator it(global_object, name, global_object,
                        LookupIterator::OWN_SKIP_INTERCEPTOR);
      Maybe<PropertyAttributes> maybe = JSReceiver::GetPropertyAttributes(&it);
      if (!maybe.IsJust()) return isolate->heap()->exception();
      if ((maybe.FromJust() & DONT_DELETE) != 0) {
        // ES#sec-globaldeclarationinstantiation 5.a:
        // If envRec.HasVarDeclaration(name) is true, throw a SyntaxError
        // exception.
        // ES#sec-globaldeclarationinstantiation 5.d:
        // If hasRestrictedGlobal is true, throw a SyntaxError exception.
        return ThrowRedeclarationError(isolate, name,
                                       RedeclarationType::kSyntaxError);
      }

      JSGlobalObject::InvalidatePropertyCell(global_object, name);
    }
  }
  return isolate->heap()->undefined_value();
}


RUNTIME_FUNCTION(Runtime_NewScriptContext) {
  HandleScope scope(isolate);
  DCHECK(args.length() == 2);

  CONVERT_ARG_HANDLE_CHECKED(JSFunction, function, 0);
  CONVERT_ARG_HANDLE_CHECKED(ScopeInfo, scope_info, 1);
  Handle<JSGlobalObject> global_object(function->context()->global_object());
  Handle<Context> native_context(global_object->native_context());
  Handle<ScriptContextTable> script_context_table(
      native_context->script_context_table());

  Object* name_clash_result =
      FindNameClash(scope_info, global_object, script_context_table);
  if (isolate->has_pending_exception()) return name_clash_result;

  // Script contexts have a canonical empty function as their closure, not the
  // anonymous closure containing the global code.  See
  // FullCodeGenerator::PushFunctionArgumentForContextAllocation.
  Handle<JSFunction> closure(
      function->shared()->IsBuiltin() ? *function : native_context->closure());
  Handle<Context> result =
      isolate->factory()->NewScriptContext(closure, scope_info);

  result->InitializeGlobalSlots();

  DCHECK(function->context() == isolate->context());
  DCHECK(*global_object == result->global_object());

  Handle<ScriptContextTable> new_script_context_table =
      ScriptContextTable::Extend(script_context_table, result);
  native_context->set_script_context_table(*new_script_context_table);
  return *result;
}


RUNTIME_FUNCTION(Runtime_NewFunctionContext) {
  HandleScope scope(isolate);
  DCHECK(args.length() == 1);

  CONVERT_ARG_HANDLE_CHECKED(JSFunction, function, 0);

  DCHECK(function->context() == isolate->context());
  int length = function->shared()->scope_info()->ContextLength();
  return *isolate->factory()->NewFunctionContext(length, function);
}


RUNTIME_FUNCTION(Runtime_PushWithContext) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  CONVERT_ARG_HANDLE_CHECKED(JSReceiver, extension_object, 0);
  CONVERT_ARG_HANDLE_CHECKED(JSFunction, function, 1);
  Handle<Context> current(isolate->context());
  Handle<Context> context =
      isolate->factory()->NewWithContext(function, current, extension_object);
  isolate->set_context(*context);
  return *context;
}


RUNTIME_FUNCTION(Runtime_PushCatchContext) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  CONVERT_ARG_HANDLE_CHECKED(String, name, 0);
  CONVERT_ARG_HANDLE_CHECKED(Object, thrown_object, 1);
  CONVERT_ARG_HANDLE_CHECKED(JSFunction, function, 2);
  Handle<Context> current(isolate->context());
  Handle<Context> context = isolate->factory()->NewCatchContext(
      function, current, name, thrown_object);
  isolate->set_context(*context);
  return *context;
}


RUNTIME_FUNCTION(Runtime_PushBlockContext) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  CONVERT_ARG_HANDLE_CHECKED(ScopeInfo, scope_info, 0);
  CONVERT_ARG_HANDLE_CHECKED(JSFunction, function, 1);
  Handle<Context> current(isolate->context());
  Handle<Context> context =
      isolate->factory()->NewBlockContext(function, current, scope_info);
  isolate->set_context(*context);
  return *context;
}


RUNTIME_FUNCTION(Runtime_DeleteLookupSlot) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  CONVERT_ARG_HANDLE_CHECKED(String, name, 0);

  int index;
  PropertyAttributes attributes;
  InitializationFlag flag;
  VariableMode mode;
  Handle<Object> holder = isolate->context()->Lookup(
      name, FOLLOW_CHAINS, &index, &attributes, &flag, &mode);

  // If the slot was not found the result is true.
  if (holder.is_null()) {
    // In case of JSProxy, an exception might have been thrown.
    if (isolate->has_pending_exception()) return isolate->heap()->exception();
    return isolate->heap()->true_value();
  }

  // If the slot was found in a context, it should be DONT_DELETE.
  if (holder->IsContext()) {
    return isolate->heap()->false_value();
  }

  // The slot was found in a JSReceiver, either a context extension object,
  // the global object, or the subject of a with.  Try to delete it
  // (respecting DONT_DELETE).
  Handle<JSReceiver> object = Handle<JSReceiver>::cast(holder);
  Maybe<bool> result = JSReceiver::DeleteProperty(object, name);
  MAYBE_RETURN(result, isolate->heap()->exception());
  return isolate->heap()->ToBoolean(result.FromJust());
}


namespace {

MaybeHandle<Object> LoadLookupSlot(Handle<String> name,
                                   Object::ShouldThrow should_throw,
                                   Handle<Object>* receiver_return = nullptr) {
  Isolate* const isolate = name->GetIsolate();

  int index;
  PropertyAttributes attributes;
  InitializationFlag flag;
  VariableMode mode;
  Handle<Object> holder = isolate->context()->Lookup(
      name, FOLLOW_CHAINS, &index, &attributes, &flag, &mode);
  if (isolate->has_pending_exception()) return MaybeHandle<Object>();

  if (index != Context::kNotFound) {
    DCHECK(holder->IsContext());
    // If the "property" we were looking for is a local variable, the
    // receiver is the global object; see ECMA-262, 3rd., 10.1.6 and 10.2.3.
    Handle<Object> receiver = isolate->factory()->undefined_value();
    Handle<Object> value = handle(Context::cast(*holder)->get(index), isolate);
    // Check for uninitialized bindings.
    if (flag == kNeedsInitialization && value->IsTheHole(isolate)) {
      THROW_NEW_ERROR(isolate,
                      NewReferenceError(MessageTemplate::kNotDefined, name),
                      Object);
    }
    DCHECK(!value->IsTheHole(isolate));
    if (receiver_return) *receiver_return = receiver;
    return value;
  }

  // Otherwise, if the slot was found the holder is a context extension
  // object, subject of a with, or a global object.  We read the named
  // property from it.
  if (!holder.is_null()) {
    // No need to unhole the value here.  This is taken care of by the
    // GetProperty function.
    Handle<Object> value;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, value, Object::GetProperty(holder, name),
        Object);
    if (receiver_return) {
      *receiver_return =
          (holder->IsJSGlobalObject() || holder->IsJSContextExtensionObject())
              ? Handle<Object>::cast(isolate->factory()->undefined_value())
              : holder;
    }
    return value;
  }

  if (should_throw == Object::THROW_ON_ERROR) {
    // The property doesn't exist - throw exception.
    THROW_NEW_ERROR(
        isolate, NewReferenceError(MessageTemplate::kNotDefined, name), Object);
  }

  // The property doesn't exist - return undefined.
  if (receiver_return) *receiver_return = isolate->factory()->undefined_value();
  return isolate->factory()->undefined_value();
}

}  // namespace


RUNTIME_FUNCTION(Runtime_LoadLookupSlot) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  CONVERT_ARG_HANDLE_CHECKED(String, name, 0);
  RETURN_RESULT_OR_FAILURE(isolate,
                           LoadLookupSlot(name, Object::THROW_ON_ERROR));
}


RUNTIME_FUNCTION(Runtime_LoadLookupSlotInsideTypeof) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  CONVERT_ARG_HANDLE_CHECKED(String, name, 0);
  RETURN_RESULT_OR_FAILURE(isolate, LoadLookupSlot(name, Object::DONT_THROW));
}


RUNTIME_FUNCTION_RETURN_PAIR(Runtime_LoadLookupSlotForCall) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DCHECK(args[0]->IsString());
  Handle<String> name = args.at<String>(0);
  Handle<Object> value;
  Handle<Object> receiver;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, value, LoadLookupSlot(name, Object::THROW_ON_ERROR, &receiver),
      MakePair(isolate->heap()->exception(), nullptr));
  return MakePair(*value, *receiver);
}


namespace {

static const int UNINITIALIZED = -2;

MaybeHandle<Object> StoreLookupSlot(Handle<String> name,
                                    Handle<Object> value,
                                    MaybeHandle<Object> label,
                                    LanguageMode language_mode) {
  Isolate* const isolate = name->GetIsolate();
  Handle<Context> context(isolate->context(), isolate);

  int index;
  PropertyAttributes attributes;
  InitializationFlag flag;
  VariableMode mode;
  int symbolic_index = UNINITIALIZED;
  Handle<Object> holder;

  if (!label.is_null()) {
    holder =
      context->Lookup(name, FOLLOW_CHAINS, &index, &attributes, &flag, &mode,
                      &symbolic_index);
  } else {
    holder =
      context->Lookup(name, FOLLOW_CHAINS, &index, &attributes, &flag, &mode);
  }

  if (holder.is_null()) {
    // In case of JSProxy, an exception might have been thrown.
    if (isolate->has_pending_exception()) return MaybeHandle<Object>();
  }

  // The property was found in a context slot.
  if (index != Context::kNotFound) {
    if (flag == kNeedsInitialization &&
        Handle<Context>::cast(holder)->is_the_hole(index)) {
      THROW_NEW_ERROR(isolate,
                      NewReferenceError(MessageTemplate::kNotDefined, name),
                      Object);
    }
    if ((attributes & READ_ONLY) == 0) {
      Handle<Context> holder_as_ctx = Handle<Context>::cast(holder);
      holder_as_ctx->set(index, *value);
      Handle<Object> next_label;
      if (label.ToHandle(&next_label)) {
        if (symbolic_index != UNINITIALIZED) {
          holder_as_ctx->set(symbolic_index, *next_label);
        }
      }
    } else if (is_strict(language_mode)) {
      // Setting read only property in strict mode.
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kStrictCannotAssign, name),
                      Object);
    }
    return value;
  }

  // Slow case: The property is not in a context slot.  It is either in a
  // context extension object, a property of the subject of a with, or a
  // property of the global object.
  Handle<JSReceiver> object;
  if (attributes != ABSENT) {
    // The property exists on the holder.
    object = Handle<JSReceiver>::cast(holder);
  } else if (is_strict(language_mode)) {
    // If absent in strict mode: throw.
    THROW_NEW_ERROR(
        isolate, NewReferenceError(MessageTemplate::kNotDefined, name), Object);
  } else {
    // If absent in sloppy mode: add the property to the global object.
    object = Handle<JSReceiver>(context->global_object());
  }

  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, value, Object::SetProperty(object, name, value, language_mode),
      Object);
  return value;
}

}  // namespace


RUNTIME_FUNCTION(Runtime_StoreLookupSlot_Sloppy) {
  HandleScope scope(isolate);
  CONVERT_ARG_HANDLE_CHECKED(String, name, 0);
  CONVERT_ARG_HANDLE_CHECKED(Object, value, 1);
  if (args.length() == 3) {
    CONVERT_ARG_HANDLE_CHECKED(Object, label, 2);
    RETURN_RESULT_OR_FAILURE(
        isolate,
        StoreLookupSlot(name, value, label, SLOPPY));
  } else {
    DCHECK(2 == args.length());
    RETURN_RESULT_OR_FAILURE(
        isolate,
        StoreLookupSlot(name, value, MaybeHandle<Object>(), SLOPPY));
  }
}


RUNTIME_FUNCTION(Runtime_StoreLookupSlot_Strict) {
  HandleScope scope(isolate);
  DCHECK(2 == args.length() || 3 == args.length());
  CONVERT_ARG_HANDLE_CHECKED(String, name, 0);
  CONVERT_ARG_HANDLE_CHECKED(Object, value, 1);
  if (args.length() == 3) {
    CONVERT_ARG_HANDLE_CHECKED(Object, label, 2);
    RETURN_RESULT_OR_FAILURE(
        isolate,
        StoreLookupSlot(name, value, label, STRICT));
  } else {
    DCHECK(2 == args.length());
    RETURN_RESULT_OR_FAILURE(
        isolate,
        StoreLookupSlot(name, value, MaybeHandle<Object>(), STRICT));
  }
}

}  // namespace internal
}  // namespace v8
