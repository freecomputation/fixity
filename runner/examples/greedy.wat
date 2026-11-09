;; The glutton: grows memory page after page. The cap refuses it,
;; memory.grow returns -1, and it reports the refusal as -7.
(module
  (memory (export "mem") 1)
  (func (export "main") (result i32)
    (local $grown i32)
    (loop $eat
      (memory.grow (i32.const 256))
      local.set $grown
      (if (i32.eq (local.get $grown) (i32.const -1))
        (then (return (i32.const -7))))
      br $eat)
    i32.const 0))
