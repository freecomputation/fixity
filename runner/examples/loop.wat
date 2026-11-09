;; The runaway: loops forever. Only the fuel meter can stop it,
;; and the meter is the point.
(module
  (func (export "main") (result i32)
    (loop $forever
      br $forever)
    i32.const 0))
