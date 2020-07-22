## Table of Contents 
- [General principles](#general-principles)
- [Naming conventions](#naming-conventions)
- [Style conventions](#style-conventions)
- [Const and exception correctness](#const-and-exception-correctness)
- [Memory management](#memory-management)
- [Containers use](#containers-use)
- [Exceptions and errors](#exceptions-and-errors)
- [Performance](#performance)

## General principles
* Clean code with clarity and consistency makes things easier to follow, understand and maintain.
* Robustness and performance firstly.

## Naming conventions
### Variables enum and classes
* Use descriptive/representative variable/class names.
* Use `g_` for global or namespace variables, e.g. `g_outputFile`.
* Use `gs_` for static at global or namespace scopes, e.g. `gs_alertsContainter`.
* Use `s_` for static variables local to a function, e.g. `s_internalMap`
* Use PascalCase for class names, as well as any aliases defined by typedef or using.
  * Exception: For classes inherited from `std::exception` it is preferable to use the standard convention, e.g. `system_error`, `runtime_error`, `dbsync_error`.
* Use PascalCase for Enum values, e.g. `enum ErrorCodes { Failure = 0, Success = 1, ...}`. Avoid the use of negative numbers for enumeration values.
* Use camelCase for function names.
* Use camelCase for variable names and parameter names.
* Constants must use ALL_CAPS_WITH_UNDERSCORES (defines or constexpr).
* Use lower-case p prefix to indicate a pointer, e.g. `pMyObject`.
* Use lower-case sp prefix to indicate a smart pointer, e.g. `spYourObject`.
* Use `m_` for instance member variables, e.g. `m_isConnected`.
  * Exception: For POD (Plain Old Data) objects it is allowed to use member variables without `m_`. This represents objects (structs) with constant values like data holders.
* Use `ms_` for static member variables, e.g. `ms_managerInstance`.

### Class methods
* Avoid repeating class names in functions which perform some action on this as a whole. For example:
  * The Employee class function to persist the entire object would be `save()` rather than `saveEmployee()`
  * But the function to delete the employee's medical data would be `deleteMedicalData()` because it doesn't act upon this as a whole. 
* Avoid using the “get” prefix for methods to obtain class attributes.

### Files and folders
* Use lower case for new folders being created.
* Use PascalCase for new files being created.
* Use descriptive related prefix for new files, e.g.: `osQueryManager.h`

## Style conventions
* Ensure your development environment is set to insert soft tabs at 4 spaces per tab.
* Braces always start on a new line apart from an empty function body which should appear on the same line, e.g. `virtual void finish() {}`.
* Always use braces after if, for, while, etc. even if only one statement in block.
* Use curly braces for initialization, e.g. `int result{ EXIT_SUCCESS };` rather than `int result = EXIT_SUCCESS;` .
* Use empty curly braces to zero-initialize C-style structs and simple data types, e.g. `size_t bufferLength{};` rather than `size_t bufferLength{ 0 };`.
* Use using instead of typedef.
* Lines must not be longer than 80-90 characters, so break out function declarations over multiple lines.
* Use alignment of parameter names, field names, assignment operators, etc. to improve legibility.
* In header files, preferred use of:
```
#ifndef _HEADER_FILENAME_H
#define _HEADER_FILENAME_H
...
#endif
```
Instead of `#pragma once`. This is not C++ standard.
* For boolean expressions avoid comparing anything with true or false , e.g. `if (isConnected == true)` should be written as if `(isConnected)`.
* For infinite loop preferred using `for (;;) {...}` rather than `while (true) {...}`.

## Const and exception correctness
* Use `const` for any object whose value does not change.
  * Exception: An object which is to be returned must not be const because this prevents use of move constructor.
* Use `const` for parameters passed by value.
* Use `const` for any instance member function which doesn’t modify this.
* Use `const` for objects of a simple type (integer, floating point, boolean, etc.), unless the callee is expected to modify the value.
* Use `const T&` for objects of a complex type T, unless the callee is expected to modify the object.
* Use `const T* const` for objects of a complex type `T` if a null reference is permitted.
* `std::shared_ptr` and `std::unique_ptr` should never be passed by value.
* Use `noexcept` for  any function which cannot throw an exception.
* Use final for any class which cannot be sub-classed.

## Memory management
The lifetime of all heap objects must be managed by a smart pointer, even if that lifetime is just a couple of a lines of code:
* Avoid using raw C pointers, instead use smart pointers as desired (`std::unique_ptr`, `std::shared_ptr`).
* For normal heap objects use the `std::unique_ptr` or `std::shared_ptr` templates. The latter must only be used when ownership of the object is shared.
* Use smart deleters along with the smart pointers to avoid memory leaks and bad frees/structure closures:
```
struct smartDeleter
{
  void operator()(<T> data)
  {
    // data free
  }
};
const std::unique_ptr<T, smartDeleter> spSomething{ };
```

## Containers use
* Preferred use of `std::vector<>` STL structure, all vector elements are placed in contiguous storage and are faster than other data types structures.
* Use `std::set<>` when it is needed to hold non-repeated data.

## Modern language features and best practices
* Use `auto` where possible instead of explicit types.
* Use `std::variant` instead of a C-style union.
* Use `std::optional` for variables and members which can legitimately be in an uninitialized state.
* Favour C++ Standard Library over Boost equivalents.
* Use C++ `nullptr` instead of `NULL`.
* Use C++ casts (`static_cast<>`, `reinterpret_cast<>`, or `const_cast<>` as appropriate) instead of C-style casts.
* If a new object is to be immediately owned by a smart pointer, construct using `std::make_shared` or `std::make_unique` instead of new .
* Avoid using magic numbers like 20, 500, 1000. Instead, define constants with meaningful names.
* Maintain one exit point apart from where exceptions are thrown.
* Member variables appearing in a constructor's initializer list must be in the same order in which the members are defined.
* The return value of non-void system/library functions calls should be checked.
* Define variables as late as possible and in the narrowest possible scope (without affecting performance).
* In derived classes, implementation of interface methods should be private or protected.
* Functions should be layered and have single responsibilities.
* A class function which does not require this must be declared static (and consider if it might be more appropriate to just have it as a non-class static function in the .cpp file).
* If a variable value will be always > to 0 used unsigned int type.
* For string values which need to represent expressions, statements, etc it is preferred the use of raw strings value for clarity and to avoid scape endings issues e.g:
  `const auto insertSql{ "{\"table\":\"processes\" ... "}]}"};`
  
   Should be replaced by:

  `const auto insertSql{ R"{"table":"processes" ... "}]}"};`

## Exceptions and errors
* Throw exceptions for any failure that is not ignorable.
* Functions must only use a result code to denote ignorable failures, e.g. a hypothetical `deleteFile()` function might return false to indicate that a file doesn't exist but would throw an exception if deletion fails for some other reason.
* In some cases, it is useful to let the caller choose if an expected failure should throw or return false, e.g. the aforementioned `deleteFile()` function might have an optional final parameter which determines if an exception should be thrown if the file doesn't exist.
* Make Win32 API calls through a wrapper which throws std::system_error on failure.

## Performance
* Avoid unnecessary copying of strings. This most frequently occurs when string is formatted in a local `char[]` or `wchar_t[]` buffer and then a `std::string` or `std::wstring` is constructed for return to the caller.
* Reserve the size of `std::vector` if you know it in advance.
* When using for-each to iterate over a container, declare the element type as `auto&` or `const auto&` as appropriate.
* In scenarios where a container must be locked to ensure safe read access but will not be modified, use `std::shared_mutex` (with `std::shared_lock`) instead of `std::mutex`.

