# Javadoc Style Guide

Write documentation comments following these conventions.

## Structure

```cpp
/** Brief one-sentence description ending with a period.

    Extended description providing more detail. Can span multiple
    paragraphs. Use backticks for `code references` inline.

    @par Preconditions
    @li Condition that must be true before calling.

    @par Effects
    Description of what the function does (the observable behavior).

    @par Postconditions
    @li Condition guaranteed true after successful return.

    @par Exception Safety
    Strong guarantee / Basic guarantee / No-throw guarantee.

    @par Thread Safety
    Thread-safe / Not thread-safe / Const operations are thread-safe.

    @par Complexity
    O(n) where n is the size of the container.

    @throws std::invalid_argument If condition.

    @note Important implementation detail or caveat.

    @par Example
    @code
    auto result = my_function(arg1, arg2);
    @endcode

    @tparam T Non-deduced template parameter description.

    @param name Single-line parameter description.
    @param other Another parameter.

    @return Description of return value.

    @see related_function
*/
```

Constructors and destructors don't have Thread Safety sections

## Section Order

1. Brief + extended description
2. `@par` sections (Preconditions, Effects, Postconditions, Exception Safety, Thread Safety, Complexity)
3. `@throws`
4. `@note`
5. `@par Example`
6. `@tparam` (non-deduced only)
7. `@param`
8. `@return`
9. `@see` (last)

## Style Rules

- **Brief description**: First sentence, concise, ends with period
- **Extended description**: After blank line, can be multiple paragraphs
- **@tparam**: Only for non-deduced template parameters (omit if deduced from arguments)
- **@param entries**: Single line each
- **@par sections**: Only include if relevant (omit empty sections)
- **Code references**: Use backticks for types, functions, parameters
- **Wrap lines**: Around 80 characters, indent continuation by 4 spaces

## Section Guidelines

| Section | Include When |
|---------|--------------|
| Preconditions | Function has requirements on inputs or state |
| Effects | Behavior isn't obvious from name/signature |
| Postconditions | Guarantees beyond "returns X" |
| Exception Safety | Function can throw or has specific guarantees |
| Thread Safety | Class/function used in concurrent contexts |
| Complexity | Non-trivial algorithmic complexity |
