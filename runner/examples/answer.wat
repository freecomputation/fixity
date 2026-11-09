;; The honest guest: does arithmetic, asks for nothing.
(module
  (func (export "main") (result i32)
    i32.const 40
    i32.const 2
    i32.add))
