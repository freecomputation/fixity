;; The petitioner: asks the host for a logging function. The runner
;; offers no imports at all, so this module is refused at the door -
;; grown code holds no ambient authority.
(module
  (import "env" "log" (func $log (param i32)))
  (func (export "main") (result i32)
    (call $log (i32.const 1))
    i32.const 0))
