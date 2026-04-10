For Rust code in this repository:

* Use `nanoserde` for JSON.
  - Use #nserde(default) for all structs.
  - Do not distinguish null and empty containers (e.g. String, Vec, Set)
  - If `nanoserde-derive` does not support the use case, write custom `DeJson` or `SerJson` impls.
* Use borrows and Cow<> instead of clones whenever possible.
* Use early return/continue to reduce nesting. Put shorter branches first.
* Write small functions and small files.
* Use functional instead of loops whenever it makes sense (except `for_each` which is no different from loops).
