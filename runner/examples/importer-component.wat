(component
  (import "log" (func $log (param "value" s32)))
  (core module $m
    (func (export "main") (result i32)
      i32.const 1))
  (core instance $i (instantiate $m))
  (func (export "main") (result s32)
    (canon lift (core func $i "main"))))
