(component
  (core module $m
    (func (export "main") (result i32)
      i32.const 42))
  (core instance $i (instantiate $m))
  (func (export "main") (result s32)
    (canon lift (core func $i "main"))))
