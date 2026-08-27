(module
 (type $0 (func (param i32 i32) (result i32)))
 (type $1 (func (result i32)))
 (type $2 (func (param i32 i32 i32 i32)))
 (type $3 (func (param i32)))
 (type $4 (func (param i32 i32 i32) (result i32)))
 (type $5 (func))
 (import "env" "abort" (func $~lib/builtins/abort (param i32 i32 i32 i32)))
 (global $~lib/rt/stub/offset (mut i32) (i32.const 0))
 (memory $0 1)
 (data $0 (i32.const 1036) "\1c\01")
 (data $0.1 (i32.const 1048) "\04\00\00\00\00\01\00\00\98/\8aB\91D7q\cf\fb\c0\b5\a5\db\b5\e9[\c2V9\f1\11\f1Y\a4\82?\92\d5^\1c\ab\98\aa\07\d8\01[\83\12\be\851$\c3}\0cUt]\ber\fe\b1\de\80\a7\06\dc\9bt\f1\9b\c1\c1i\9b\e4\86G\be\ef\c6\9d\c1\0f\cc\a1\0c$o,\e9-\aa\84tJ\dc\a9\b0\\\da\88\f9vRQ>\98m\c61\a8\c8\'\03\b0\c7\7fY\bf\f3\0b\e0\c6G\91\a7\d5Qc\ca\06g))\14\85\n\b7\'8!\1b.\fcm,M\13\r8STs\ne\bb\njv.\c9\c2\81\85,r\92\a1\e8\bf\a2Kf\1a\a8p\8bK\c2\a3Ql\c7\19\e8\92\d1$\06\99\d6\855\0e\f4p\a0j\10\16\c1\a4\19\08l7\1eLwH\'\b5\bc\b04\b3\0c\1c9J\aa\d8NO\ca\9c[\f3o.h\ee\82\8ftoc\a5x\14x\c8\84\08\02\c7\8c\fa\ff\be\90\eblP\a4\f7\a3\f9\be\f2xq\c6")
 (data $1 (i32.const 1324) "<")
 (data $1.1 (i32.const 1336) "\02\00\00\00$\00\00\00I\00n\00d\00e\00x\00 \00o\00u\00t\00 \00o\00f\00 \00r\00a\00n\00g\00e")
 (data $2 (i32.const 1388) "<")
 (data $2.1 (i32.const 1400) "\02\00\00\00&\00\00\00~\00l\00i\00b\00/\00s\00t\00a\00t\00i\00c\00a\00r\00r\00a\00y\00.\00t\00s")
 (data $3 (i32.const 1452) "<")
 (data $3.1 (i32.const 1464) "\02\00\00\00(\00\00\00A\00l\00l\00o\00c\00a\00t\00i\00o\00n\00 \00t\00o\00o\00 \00l\00a\00r\00g\00e")
 (data $4 (i32.const 1516) "<")
 (data $4.1 (i32.const 1528) "\02\00\00\00\1e\00\00\00~\00l\00i\00b\00/\00r\00t\00/\00s\00t\00u\00b\00.\00t\00s")
 (export "saltPtr" (func $pow/saltPtr))
 (export "solve" (func $pow/solve))
 (export "hashBits" (func $pow/hashBits))
 (export "memory" (memory $0))
 (start $~start)
 (func $pow/saltPtr (result i32)
  i32.const 1024
 )
 (func $~lib/staticarray/StaticArray<u32>#__get (param $0 i32) (param $1 i32) (result i32)
  local.get $1
  local.get $0
  i32.const 20
  i32.sub
  i32.load offset=16
  i32.const 2
  i32.shr_u
  i32.ge_u
  if
   i32.const 1344
   i32.const 1408
   i32.const 78
   i32.const 41
   call $~lib/builtins/abort
   unreachable
  end
  local.get $0
  local.get $1
  i32.const 2
  i32.shl
  i32.add
  i32.load
 )
 (func $pow/sha256 (param $0 i32)
  (local $1 i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (local $9 i32)
  (local $10 i32)
  (local $11 i32)
  (local $12 i32)
  (local $13 i32)
  (local $14 i32)
  (local $15 i32)
  (local $16 i32)
  (local $17 i32)
  (local $18 i32)
  (local $19 i32)
  (local $20 i64)
  (local $21 i32)
  i32.const 1779033703
  local.set $8
  i32.const -1150833019
  local.set $9
  i32.const 1013904242
  local.set $10
  i32.const -1521486534
  local.set $11
  i32.const 1359893119
  local.set $12
  i32.const -1694144372
  local.set $13
  i32.const 528734635
  local.set $14
  i32.const 1541459225
  local.set $15
  local.get $0
  i64.extend_i32_s
  i64.const 3
  i64.shl
  local.set $20
  local.get $0
  i32.const 1
  i32.add
  local.set $1
  loop $while-continue|0
   local.get $1
   i32.const 63
   i32.and
   i32.const 56
   i32.ne
   if
    local.get $1
    i32.const 1
    i32.add
    local.set $1
    br $while-continue|0
   end
  end
  local.get $1
  i32.const 8
  i32.add
  local.set $17
  loop $for-loop|1
   local.get $2
   local.get $17
   i32.lt_s
   if
    local.get $2
    i32.const 2048
    i32.add
    i32.const 0
    i32.store8
    local.get $2
    i32.const 1
    i32.add
    local.set $2
    br $for-loop|1
   end
  end
  i32.const 2048
  i32.const 1280
  local.get $0
  memory.copy
  local.get $0
  i32.const 2048
  i32.add
  i32.const 128
  i32.store8
  i32.const 0
  local.set $1
  loop $for-loop|2
   local.get $1
   i32.const 8
   i32.lt_s
   if
    local.get $17
    i32.const 2047
    i32.add
    local.get $1
    i32.sub
    local.get $20
    local.get $1
    i64.extend_i32_s
    i64.const 3
    i64.shl
    i64.shr_u
    i64.const 255
    i64.and
    i64.store8
    local.get $1
    i32.const 1
    i32.add
    local.set $1
    br $for-loop|2
   end
  end
  loop $for-loop|3
   local.get $17
   local.get $18
   i32.gt_s
   if
    i32.const 0
    local.set $1
    loop $for-loop|4
     local.get $1
     i32.const 16
     i32.lt_s
     if
      local.get $1
      i32.const 2
      i32.shl
      local.tee $0
      local.get $18
      i32.const 2048
      i32.add
      i32.add
      local.set $2
      local.get $0
      i32.const 1600
      i32.add
      local.get $2
      i32.load8_u offset=3
      local.get $2
      i32.load8_u
      i32.const 24
      i32.shl
      local.get $2
      i32.load8_u offset=1
      i32.const 16
      i32.shl
      i32.or
      local.get $2
      i32.load8_u offset=2
      i32.const 8
      i32.shl
      i32.or
      i32.or
      i32.store
      local.get $1
      i32.const 1
      i32.add
      local.set $1
      br $for-loop|4
     end
    end
    i32.const 16
    local.set $1
    loop $for-loop|5
     local.get $1
     i32.const 64
     i32.lt_s
     if
      local.get $1
      i32.const 2
      i32.shl
      local.tee $0
      i32.const 1592
      i32.add
      i32.load
      local.set $2
      local.get $0
      i32.const 1600
      i32.add
      local.get $0
      i32.const 1572
      i32.add
      i32.load
      local.get $0
      i32.const 1536
      i32.add
      i32.load
      local.get $0
      i32.const 1540
      i32.add
      i32.load
      local.tee $0
      i32.const 25
      i32.shl
      local.get $0
      i32.const 7
      i32.shr_u
      i32.or
      local.get $0
      i32.const 14
      i32.shl
      local.get $0
      i32.const 18
      i32.shr_u
      i32.or
      i32.xor
      local.get $0
      i32.const 3
      i32.shr_u
      i32.xor
      i32.add
      i32.add
      local.get $2
      i32.const 15
      i32.shl
      local.get $2
      i32.const 17
      i32.shr_u
      i32.or
      local.get $2
      i32.const 13
      i32.shl
      local.get $2
      i32.const 19
      i32.shr_u
      i32.or
      i32.xor
      local.get $2
      i32.const 10
      i32.shr_u
      i32.xor
      i32.add
      i32.store
      local.get $1
      i32.const 1
      i32.add
      local.set $1
      br $for-loop|5
     end
    end
    local.get $8
    local.set $5
    local.get $9
    local.set $1
    local.get $10
    local.set $0
    local.get $11
    local.set $7
    local.get $12
    local.set $6
    local.get $13
    local.set $2
    local.get $14
    local.set $3
    local.get $15
    local.set $4
    i32.const 0
    local.set $16
    loop $for-loop|6
     local.get $16
     i32.const 64
     i32.lt_s
     if
      i32.const 1056
      local.get $16
      call $~lib/staticarray/StaticArray<u32>#__get
      local.get $4
      local.get $6
      i32.const 7
      i32.shl
      local.get $6
      i32.const 25
      i32.shr_u
      i32.or
      local.get $6
      i32.const 26
      i32.shl
      local.get $6
      i32.const 6
      i32.shr_u
      i32.or
      local.get $6
      i32.const 21
      i32.shl
      local.get $6
      i32.const 11
      i32.shr_u
      i32.or
      i32.xor
      i32.xor
      i32.add
      local.get $2
      local.get $6
      i32.and
      local.get $6
      i32.const -1
      i32.xor
      local.get $3
      i32.and
      i32.xor
      i32.add
      i32.add
      local.get $16
      i32.const 2
      i32.shl
      i32.const 1600
      i32.add
      i32.load
      i32.add
      local.set $19
      local.get $5
      i32.const 10
      i32.shl
      local.get $5
      i32.const 22
      i32.shr_u
      i32.or
      local.get $5
      i32.const 30
      i32.shl
      local.get $5
      i32.const 2
      i32.shr_u
      i32.or
      local.get $5
      i32.const 19
      i32.shl
      local.get $5
      i32.const 13
      i32.shr_u
      i32.or
      i32.xor
      i32.xor
      local.get $0
      local.get $1
      i32.and
      local.get $1
      local.get $5
      i32.and
      local.get $0
      local.get $5
      i32.and
      i32.xor
      i32.xor
      i32.add
      local.set $21
      local.get $3
      local.set $4
      local.get $2
      local.set $3
      local.get $6
      local.set $2
      local.get $7
      local.get $19
      i32.add
      local.set $6
      local.get $0
      local.set $7
      local.get $1
      local.set $0
      local.get $5
      local.set $1
      local.get $19
      local.get $21
      i32.add
      local.set $5
      local.get $16
      i32.const 1
      i32.add
      local.set $16
      br $for-loop|6
     end
    end
    local.get $5
    local.get $8
    i32.add
    local.set $8
    local.get $1
    local.get $9
    i32.add
    local.set $9
    local.get $0
    local.get $10
    i32.add
    local.set $10
    local.get $7
    local.get $11
    i32.add
    local.set $11
    local.get $6
    local.get $12
    i32.add
    local.set $12
    local.get $2
    local.get $13
    i32.add
    local.set $13
    local.get $3
    local.get $14
    i32.add
    local.set $14
    local.get $4
    local.get $15
    i32.add
    local.set $15
    local.get $18
    i32.const -64
    i32.sub
    local.set $18
    br $for-loop|3
   end
  end
  global.get $~lib/rt/stub/offset
  local.set $0
  global.get $~lib/rt/stub/offset
  i32.const 4
  i32.add
  local.tee $1
  i32.const 60
  i32.add
  local.tee $2
  memory.size
  local.tee $3
  i32.const 16
  i32.shl
  i32.const 15
  i32.add
  i32.const -16
  i32.and
  local.tee $4
  i32.gt_u
  if
   local.get $3
   local.get $2
   local.get $4
   i32.sub
   i32.const 65535
   i32.add
   i32.const -65536
   i32.and
   i32.const 16
   i32.shr_u
   local.tee $4
   local.get $3
   local.get $4
   i32.gt_s
   select
   memory.grow
   i32.const 0
   i32.lt_s
   if
    local.get $4
    memory.grow
    i32.const 0
    i32.lt_s
    if
     unreachable
    end
   end
  end
  local.get $2
  global.set $~lib/rt/stub/offset
  local.get $0
  i32.const 60
  i32.store
  local.get $1
  i32.const 4
  i32.sub
  local.tee $0
  i32.const 0
  i32.store offset=4
  local.get $0
  i32.const 0
  i32.store offset=8
  local.get $0
  i32.const 4
  i32.store offset=12
  local.get $0
  i32.const 32
  i32.store offset=16
  local.get $1
  i32.const 16
  i32.add
  local.tee $0
  local.get $8
  i32.store
  local.get $0
  local.get $9
  i32.store offset=4
  local.get $0
  local.get $10
  i32.store offset=8
  local.get $0
  local.get $11
  i32.store offset=12
  local.get $0
  local.get $12
  i32.store offset=16
  local.get $0
  local.get $13
  i32.store offset=20
  local.get $0
  local.get $14
  i32.store offset=24
  local.get $0
  local.get $15
  i32.store offset=28
  i32.const 0
  local.set $1
  loop $for-loop|7
   local.get $1
   i32.const 8
   i32.lt_s
   if
    local.get $1
    i32.const 2
    i32.shl
    local.tee $2
    i32.const 1536
    i32.add
    local.get $0
    local.get $1
    call $~lib/staticarray/StaticArray<u32>#__get
    local.tee $3
    i32.const 24
    i32.shr_u
    i32.store8
    local.get $2
    i32.const 1537
    i32.add
    local.get $3
    i32.const 16
    i32.shr_u
    i32.store8
    local.get $2
    i32.const 1538
    i32.add
    local.get $3
    i32.const 8
    i32.shr_u
    i32.store8
    local.get $2
    i32.const 1539
    i32.add
    local.get $3
    i32.store8
    local.get $1
    i32.const 1
    i32.add
    local.set $1
    br $for-loop|7
   end
  end
 )
 (func $pow/solve (param $0 i32) (param $1 i32) (param $2 i32) (result i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  loop $for-loop|0
   local.get $2
   local.get $4
   i32.gt_s
   if
    i32.const 1280
    i32.const 1024
    local.get $0
    memory.copy
    local.get $0
    i32.const 1280
    i32.add
    local.set $5
    block $__inlined_func$pow/itoa$26
     local.get $4
     i32.eqz
     if
      local.get $5
      i32.const 48
      i32.store8
      i32.const 1
      local.set $6
      br $__inlined_func$pow/itoa$26
     end
     i32.const 0
     local.set $6
     local.get $4
     local.tee $3
     local.set $7
     loop $while-continue|0
      local.get $7
      i32.const 0
      i32.gt_s
      if
       local.get $6
       i32.const 1
       i32.add
       local.set $6
       local.get $7
       i32.const 10
       i32.div_s
       local.set $7
       br $while-continue|0
      end
     end
     local.get $6
     i32.const 1
     i32.sub
     local.set $7
     loop $while-continue|1
      local.get $3
      i32.const 0
      i32.gt_s
      if
       local.get $5
       local.get $7
       i32.add
       local.get $3
       i32.const 10
       i32.rem_s
       i32.const 48
       i32.add
       i32.store8
       local.get $3
       i32.const 10
       i32.div_s
       local.set $3
       local.get $7
       i32.const 1
       i32.sub
       local.set $7
       br $while-continue|1
      end
     end
    end
    local.get $0
    local.get $6
    i32.add
    call $pow/sha256
    i32.const 0
    local.set $6
    i32.const 0
    local.set $3
    loop $for-loop|00
     local.get $3
     i32.const 32
     i32.lt_s
     if
      block $for-break0
       block $for-continue|0
        local.get $3
        i32.const 1536
        i32.add
        i32.load8_u
        local.tee $5
        i32.eqz
        if
         local.get $6
         i32.const 8
         i32.add
         local.set $6
         br $for-continue|0
        end
        i32.const 128
        local.set $3
        i32.const 0
        local.set $7
        loop $while-continue|12
         local.get $3
         local.get $5
         i32.and
         i32.const 1
         local.get $3
         select
         i32.eqz
         if
          local.get $7
          i32.const 1
          i32.add
          local.set $7
          local.get $3
          i32.const 1
          i32.shr_u
          local.set $3
          br $while-continue|12
         end
        end
        local.get $6
        local.get $7
        i32.add
        local.set $6
        br $for-break0
       end
       local.get $3
       i32.const 1
       i32.add
       local.set $3
       br $for-loop|00
      end
     end
    end
    local.get $1
    local.get $6
    i32.le_s
    if
     local.get $4
     return
    end
    local.get $4
    i32.const 1
    i32.add
    local.set $4
    br $for-loop|0
   end
  end
  i32.const -1
 )
 (func $pow/hashBits (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  i32.const 1280
  i32.const 1024
  local.get $0
  memory.copy
  local.get $0
  local.tee $3
  i32.const 1280
  i32.add
  local.set $4
  block $__inlined_func$pow/itoa$28
   local.get $1
   i32.eqz
   if
    local.get $4
    i32.const 48
    i32.store8
    i32.const 1
    local.set $0
    br $__inlined_func$pow/itoa$28
   end
   i32.const 0
   local.set $0
   local.get $1
   local.set $2
   loop $while-continue|0
    local.get $2
    i32.const 0
    i32.gt_s
    if
     local.get $0
     i32.const 1
     i32.add
     local.set $0
     local.get $2
     i32.const 10
     i32.div_s
     local.set $2
     br $while-continue|0
    end
   end
   local.get $0
   i32.const 1
   i32.sub
   local.set $2
   loop $while-continue|1
    local.get $1
    i32.const 0
    i32.gt_s
    if
     local.get $2
     local.get $4
     i32.add
     local.get $1
     i32.const 10
     i32.rem_s
     i32.const 48
     i32.add
     i32.store8
     local.get $1
     i32.const 10
     i32.div_s
     local.set $1
     local.get $2
     i32.const 1
     i32.sub
     local.set $2
     br $while-continue|1
    end
   end
  end
  local.get $0
  local.get $3
  i32.add
  call $pow/sha256
  i32.const 0
  local.set $1
  i32.const 0
  local.set $0
  loop $for-loop|0
   local.get $0
   i32.const 32
   i32.lt_s
   if
    block $for-break0
     block $for-continue|0
      local.get $0
      i32.const 1536
      i32.add
      i32.load8_u
      local.tee $3
      i32.eqz
      if
       local.get $1
       i32.const 8
       i32.add
       local.set $1
       br $for-continue|0
      end
      i32.const 128
      local.set $0
      i32.const 0
      local.set $2
      loop $while-continue|11
       local.get $0
       local.get $3
       i32.and
       i32.const 1
       local.get $0
       select
       i32.eqz
       if
        local.get $2
        i32.const 1
        i32.add
        local.set $2
        local.get $0
        i32.const 1
        i32.shr_u
        local.set $0
        br $while-continue|11
       end
      end
      local.get $1
      local.get $2
      i32.add
      local.set $1
      br $for-break0
     end
     local.get $0
     i32.const 1
     i32.add
     local.set $0
     br $for-loop|0
    end
   end
  end
  local.get $1
 )
 (func $~start
  i32.const 1580
  global.set $~lib/rt/stub/offset
 )
)
