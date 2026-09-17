//! G4/TASK-020 three-way differential: raw-hardware plain code vs
//! superop-emitted code vs the software oracle — bit-exact on every case.
//!
//! A skip on a non-Windows host is not a pass (same policy as os_load.rs).

#[cfg(not(windows))]
#[test]
fn semantics_diff_not_executed() {
    eprintln!(
        "BLOCKED: semantics differential tests did not run (host is not Windows). \
         This is not a G4 pass."
    );
    if std::env::var("XL_REQUIRE_TARGET_LOAD").as_deref() == Ok("1") {
        panic!("XL_REQUIRE_TARGET_LOAD=1 but this host cannot JIT x64 code");
    }
}

#[cfg(windows)]
mod diff {
    use iced_x86::code_asm::*;
    use xenolith_vm::ir::*;
    use xenolith_vm::semantics::MachineState;
    use xenolith_vm::{emit_superop, Abi};

    // ------------------------------------------------------------------
    // JIT harness (RW → copy → RX; mirrors the product's W^X discipline).
    // ------------------------------------------------------------------
    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualAlloc(addr: *const u8, size: usize, ty: u32, prot: u32) -> *mut u8;
        fn VirtualProtect(
            addr: *mut u8,
            size: usize,
            prot: u32,
            old: *mut u32,
        ) -> i32;
        fn VirtualFree(addr: *mut u8, size: usize, ty: u32) -> i32;
    }

    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const MEM_RELEASE: u32 = 0x8000;

    struct Jit(*mut u8);
    impl Drop for Jit {
        fn drop(&mut self) {
            unsafe { VirtualFree(self.0, 0, MEM_RELEASE) };
        }
    }

    impl Jit {
        fn new(code: &[u8]) -> Self {
            unsafe {
                let p = VirtualAlloc(std::ptr::null(), 0x1000, MEM_COMMIT_RESERVE, PAGE_READWRITE);
                assert!(!p.is_null(), "VirtualAlloc failed");
                std::ptr::copy_nonoverlapping(code.as_ptr(), p, code.len());
                let mut old = 0u32;
                assert_eq!(VirtualProtect(p, 0x1000, PAGE_EXECUTE_READ, &mut old), 1);
                Jit(p)
            }
        }

        /// `f(buf)` — one pointer argument in RCX (Win64).
        unsafe fn call(&self, buf: *mut u8) {
            let f: extern "system" fn(*mut u8) = std::mem::transmute(self.0);
            f(buf)
        }
    }

    // ------------------------------------------------------------------
    // Deterministic PRNG + float edge patterns.
    // ------------------------------------------------------------------
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn f32_edges() -> Vec<u32> {
        vec![
            0x0000_0000,          // +0
            0x8000_0000,          // -0
            0x7F80_0000,          // +inf
            0xFF80_0000,          // -inf
            0x7FC0_0000,          // QNaN
            0xFFC0_0000,          // -QNaN
            0x7F80_0001,          // SNaN
            0x0000_0001,          // smallest denormal
            0x007F_FFFF,          // largest denormal
            0x0080_0000,          // smallest normal
            0x7F7F_FFFF,          // largest normal
            0xFF7F_FFFF,          // -largest normal
            0x3F80_0000,          // 1.0
            0xBF80_0000,          // -1.0
            0x4049_0FDB,          // pi
            0x4B00_0000,          // 2^23 (tie boundary)
        ]
    }

    fn f64_edges() -> Vec<u64> {
        vec![
            0x0000_0000_0000_0000,
            0x8000_0000_0000_0000,
            0x7FF0_0000_0000_0000,
            0xFFF0_0000_0000_0000,
            0x7FF8_0000_0000_0000,
            0xFFF8_0000_0000_0000,
            0x7FF0_0000_0000_0001,
            0x0000_0000_0000_0001,
            0x000F_FFFF_FFFF_FFFF,
            0x0010_0000_0000_0000,
            0x7FEF_FFFF_FFFF_FFFF,
            0x3FF0_0000_0000_0000,
            0xBFF0_0000_0000_0000,
            0x4009_21FB_5444_2D18,
            0x4330_0000_0000_0000,
        ]
    }

    // ------------------------------------------------------------------
    // IR builders (loads/stores ride [RCX+off]; the superop calling
    // convention carries the buffer pointer in RCX).
    // ------------------------------------------------------------------
    const B: u8 = VREG_RCX;
    const L: u8 = 5; // lhs / a_lo
    const H: u8 = 6; // rhs / a_hi
    const D: u8 = 7; // dst / b_lo
    const E: u8 = 8; // b_hi
    const G: u8 = 9; // dst_hi

    fn scalar_ir(stmt: Stmt) -> IrModule {
        IrModule {
            entry: 0,
            blocks: vec![IrBlock {
                stmts: vec![
                    Stmt::Load { dst: L, addr: addr(0), width: 8 },
                    Stmt::Load { dst: H, addr: addr(8), width: 8 },
                    stmt,
                    Stmt::Store { addr: addr(16), src: Src::Reg(D), width: 8 },
                ],
                term: Term::Ret,
            }],
        }
    }

    fn addr(disp: i32) -> Addr {
        Addr::BaseDisp { base: B, disp }
    }

    fn fscalar_ir(op: FOp, width: FWidth) -> IrModule {
        scalar_ir(Stmt::FScalar { op, width, dst: D, lhs: Src::Reg(L), rhs: Src::Reg(H) })
    }

    fn fcvt_ir(kind: CvtKind) -> IrModule {
        scalar_ir(Stmt::FCvt { kind, dst: D, src: Src::Reg(L) })
    }

    fn fcmp_ir(width: FWidth) -> IrModule {
        scalar_ir(Stmt::FCmp { width, dst: D, lhs: Src::Reg(L), rhs: Src::Reg(H) })
    }

    fn vec_ir(op: VecOp) -> IrModule {
        IrModule {
            entry: 0,
            blocks: vec![IrBlock {
                stmts: vec![
                    Stmt::Load { dst: L, addr: addr(0), width: 8 },
                    Stmt::Load { dst: H, addr: addr(8), width: 8 },
                    Stmt::Load { dst: D, addr: addr(16), width: 8 },
                    Stmt::Load { dst: E, addr: addr(24), width: 8 },
                    Stmt::VecBin {
                        op,
                        dst: D,
                        dst_hi: G,
                        lhs_lo: Src::Reg(L),
                        lhs_hi: Src::Reg(H),
                        rhs_lo: Src::Reg(D),
                        rhs_hi: Src::Reg(E),
                    },
                    Stmt::Store { addr: addr(32), src: Src::Reg(D), width: 8 },
                    Stmt::Store { addr: addr(40), src: Src::Reg(G), width: 8 },
                ],
                term: Term::Ret,
            }],
        }
    }

    fn atomic_ir(op: AtomicOpIr, width: u8) -> IrModule {
        IrModule {
            entry: 0,
            blocks: vec![IrBlock {
                stmts: vec![
                    Stmt::Load { dst: L, addr: addr(16), width: 8 }, // expect
                    Stmt::Load { dst: H, addr: addr(8), width: 8 },  // incoming
                    Stmt::Atomic {
                        op,
                        addr: addr(0),
                        width,
                        expect: L,
                        incoming: Src::Reg(H),
                        dst: D,
                        zf_dst: G,
                    },
                    Stmt::Store { addr: addr(24), src: Src::Reg(D), width: 8 },
                    Stmt::Store { addr: addr(32), src: Src::Reg(G), width: 8 },
                ],
                term: Term::Ret,
            }],
        }
    }

    // ------------------------------------------------------------------
    // Three-way runner. `plain` emits the raw hardware reference.
    // ------------------------------------------------------------------
    const ORACLE_BASE: u64 = 0x0000_0010_0000_0000;

    fn oracle_run(ir: &IrModule, buf: &mut [u8], out_off: usize, out_len: usize) -> Vec<u8> {
        let mut st = MachineState::new(Abi::Win64);
        st.width = crate_width64();
        st.gpr[B as usize] = ORACLE_BASE;
        st.mem.write_bytes(ORACLE_BASE, buf).unwrap();
        // Loads use [RCX+disp]: precompute disp by re-running is not needed;
        // the MachineState memory holds the whole buffer already.
        let _ = xenolith_vm::semantics::eval_machine(ir, &mut st).expect("oracle eval");
        st.mem.read_bytes(ORACLE_BASE + out_off as u64, out_len).unwrap()
    }

    fn crate_width64() -> xenolith_vm::semantics::Width {
        xenolith_vm::semantics::Width::B64
    }

    fn superop_run(ir: &IrModule, buf: &mut [u8], out_off: usize, out_len: usize) -> Vec<u8> {
        let code = emit_superop(ir, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 1, 2, 3, 4, 5, 6, 7, 8])
            .expect("emit superop");
        let jit = Jit::new(&code);
        unsafe { jit.call(buf.as_mut_ptr()) };
        buf[out_off..out_off + out_len].to_vec()
    }

    fn plain_run(asm: Vec<u8>, buf: &mut [u8], out_off: usize, out_len: usize) -> Vec<u8> {
        let jit = Jit::new(&asm);
        unsafe { jit.call(buf.as_mut_ptr()) };
        buf[out_off..out_off + out_len].to_vec()
    }

    fn assert_three_way(
        name: &str,
        ir: &IrModule,
        plain: Vec<u8>,
        buf: &mut [u8],
        out_off: usize,
        out_len: usize,
    ) {
        let mut b2 = buf.to_vec();
        let mut b3 = buf.to_vec();
        let o = oracle_run(ir, &mut b2, out_off, out_len);
        let s = superop_run(ir, &mut b3, out_off, out_len);
        let p = plain_run(plain, buf, out_off, out_len);
        assert_eq!(p, o, "{name}: plain != oracle (buf restored {:?})", &buf[..out_off.min(buf.len())]);
        assert_eq!(s, o, "{name}: superop != oracle");
    }

    // ------------------------------------------------------------------
    // Plain-reference emitters (raw hardware, volatile regs only).
    // ------------------------------------------------------------------
    fn asm_code(f: impl FnOnce(&mut CodeAssembler) -> Result<(), iced_x86::IcedError>) -> Vec<u8> {
        let mut a = CodeAssembler::new(64).unwrap();
        f(&mut a).unwrap();
        a.assemble(0).unwrap()
    }

    fn plain_f32(op: FOp) -> Vec<u8> {
        asm_code(|a| {
            a.movd(xmm0, dword_ptr(rcx))?;
            a.movd(xmm1, dword_ptr(rcx + 8i32))?;
            match op {
                FOp::Add => a.addss(xmm0, xmm1)?,
                FOp::Sub => a.subss(xmm0, xmm1)?,
                FOp::Mul => a.mulss(xmm0, xmm1)?,
                FOp::Div => a.divss(xmm0, xmm1)?,
                FOp::Min => a.minss(xmm0, xmm1)?,
                FOp::Max => a.maxss(xmm0, xmm1)?,
                FOp::Sqrt => a.sqrtss(xmm0, xmm0)?,
            }
            a.movd(dword_ptr(rcx + 16i32), xmm0)?;
            a.ret()
        })
    }

    fn plain_f64(op: FOp) -> Vec<u8> {
        asm_code(|a| {
            a.movq(xmm0, qword_ptr(rcx))?;
            a.movq(xmm1, qword_ptr(rcx + 8i32))?;
            match op {
                FOp::Add => a.addsd(xmm0, xmm1)?,
                FOp::Sub => a.subsd(xmm0, xmm1)?,
                FOp::Mul => a.mulsd(xmm0, xmm1)?,
                FOp::Div => a.divsd(xmm0, xmm1)?,
                FOp::Min => a.minsd(xmm0, xmm1)?,
                FOp::Max => a.maxsd(xmm0, xmm1)?,
                FOp::Sqrt => a.sqrtsd(xmm0, xmm0)?,
            }
            a.movq(qword_ptr(rcx + 16i32), xmm0)?;
            a.ret()
        })
    }

    fn plain_x87(op: FOp) -> Vec<u8> {
        asm_code(|a| {
            a.sub(rsp, 16i32)?;
            a.mov(rax, qword_ptr(rcx))?;
            a.mov(qword_ptr(rsp), rax)?;
            a.fld(qword_ptr(rsp))?;
            if matches!(op, FOp::Sqrt) {
                a.fsqrt()?;
            } else {
                a.mov(rax, qword_ptr(rcx + 8i32))?;
                a.mov(qword_ptr(rsp), rax)?;
                a.fld(qword_ptr(rsp))?;
                match op {
                    FOp::Add => a.faddp(st1, st0)?,
                    FOp::Sub => a.fsubp(st1, st0)?,
                    FOp::Mul => a.fmulp(st1, st0)?,
                    FOp::Div => a.fdivp(st1, st0)?,
                    _ => a.faddp(st1, st0)?,
                }
            }
            a.fstp(qword_ptr(rsp))?;
            a.mov(rax, qword_ptr(rsp))?;
            a.mov(qword_ptr(rcx + 16i32), rax)?;
            a.add(rsp, 16i32)?;
            a.ret()
        })
    }

    fn plain_fcvt(kind: CvtKind) -> Vec<u8> {
        asm_code(|a| {
            // Integer sources load their operand from [rcx] first; the
            // buffer pointer itself is not the operand.
            match kind {
                CvtKind::I32F32 => {
                    a.mov(eax, dword_ptr(rcx))?;
                    a.cvtsi2ss(xmm0, eax)?;
                    a.movd(dword_ptr(rcx + 16i32), xmm0)?;
                }
                CvtKind::I32F64 => {
                    a.mov(eax, dword_ptr(rcx))?;
                    a.cvtsi2sd(xmm0, eax)?;
                    a.movq(qword_ptr(rcx + 16i32), xmm0)?;
                }
                CvtKind::I64F32 => {
                    a.mov(rax, qword_ptr(rcx))?;
                    a.cvtsi2ss(xmm0, rax)?;
                    a.movd(dword_ptr(rcx + 16i32), xmm0)?;
                }
                CvtKind::I64F64 => {
                    a.mov(rax, qword_ptr(rcx))?;
                    a.cvtsi2sd(xmm0, rax)?;
                    a.movq(qword_ptr(rcx + 16i32), xmm0)?;
                }
                CvtKind::F32I32T => {
                    a.movd(xmm0, dword_ptr(rcx))?;
                    a.cvttss2si(eax, xmm0)?;
                    a.mov(dword_ptr(rcx + 16i32), eax)?;
                }
                CvtKind::F64I32T => {
                    a.movq(xmm0, qword_ptr(rcx))?;
                    a.cvttsd2si(eax, xmm0)?;
                    a.mov(dword_ptr(rcx + 16i32), eax)?;
                }
                CvtKind::F32I64T => {
                    a.movd(xmm0, dword_ptr(rcx))?;
                    a.cvttss2si(rax, xmm0)?;
                    a.mov(qword_ptr(rcx + 16i32), rax)?;
                }
                CvtKind::F64I64T => {
                    a.movq(xmm0, qword_ptr(rcx))?;
                    a.cvttsd2si(rax, xmm0)?;
                    a.mov(qword_ptr(rcx + 16i32), rax)?;
                }
                CvtKind::F32I32R => {
                    a.movd(xmm0, dword_ptr(rcx))?;
                    a.cvtss2si(eax, xmm0)?;
                    a.mov(dword_ptr(rcx + 16i32), eax)?;
                }
                CvtKind::F64I64R => {
                    a.movq(xmm0, qword_ptr(rcx))?;
                    a.cvtsd2si(rax, xmm0)?;
                    a.mov(qword_ptr(rcx + 16i32), rax)?;
                }
                CvtKind::F32F64 => {
                    a.movd(xmm0, dword_ptr(rcx))?;
                    a.cvtss2sd(xmm0, xmm0)?;
                    a.movq(qword_ptr(rcx + 16i32), xmm0)?;
                }
                CvtKind::F64F32 => {
                    a.movq(xmm0, qword_ptr(rcx))?;
                    a.cvtsd2ss(xmm0, xmm0)?;
                    a.movd(dword_ptr(rcx + 16i32), xmm0)?;
                }
            }
            a.ret()
        })
    }



    fn plain_fcmp(width: FWidth) -> Vec<u8> {
        asm_code(|a| {
            a.xor(eax, eax)?;
            match width {
                FWidth::F32 => {
                    a.movd(xmm0, dword_ptr(rcx))?;
                    a.movd(xmm1, dword_ptr(rcx + 8i32))?;
                    a.ucomiss(xmm0, xmm1)?;
                }
                _ => {
                    a.movq(xmm0, qword_ptr(rcx))?;
                    a.movq(xmm1, qword_ptr(rcx + 8i32))?;
                    a.ucomisd(xmm0, xmm1)?;
                }
            }
            let mut l_unord = a.create_label();
            let mut l_gt = a.create_label();
            let mut l_lt = a.create_label();
            let mut l_done = a.create_label();
            a.jp(l_unord)?;
            a.ja(l_gt)?;
            a.jb(l_lt)?;
            a.jmp(l_done)?;
            a.set_label(&mut l_unord)?;
            a.mov(eax, 3u32)?;
            a.jmp(l_done)?;
            a.set_label(&mut l_gt)?;
            a.mov(eax, 1u32)?;
            a.jmp(l_done)?;
            a.set_label(&mut l_lt)?;
            a.mov(eax, 2u32)?;
            a.set_label(&mut l_done)?;
            a.mov(dword_ptr(rcx + 16i32), eax)?;
            a.ret()
        })
    }

    fn plain_vec(op: VecOp) -> Vec<u8> {
        asm_code(|a| {
            a.movq(xmm0, qword_ptr(rcx))?;
            a.pinsrq(xmm0, qword_ptr(rcx + 8i32), 1)?;
            a.movq(xmm1, qword_ptr(rcx + 16i32))?;
            a.pinsrq(xmm1, qword_ptr(rcx + 24i32), 1)?;
            match op {
                VecOp::PAddD => a.paddd(xmm0, xmm1)?,
                VecOp::PSubD => a.psubd(xmm0, xmm1)?,
                VecOp::PMulLW => a.pmullw(xmm0, xmm1)?,
                VecOp::PMulHW => a.pmulhw(xmm0, xmm1)?,
                VecOp::PMulLD => a.pmulld(xmm0, xmm1)?,
                VecOp::PMinSD => a.pminsd(xmm0, xmm1)?,
                VecOp::PMaxSD => a.pmaxsd(xmm0, xmm1)?,
                VecOp::PAnd => a.pand(xmm0, xmm1)?,
                VecOp::POr => a.por(xmm0, xmm1)?,
                VecOp::PXor => a.pxor(xmm0, xmm1)?,
                VecOp::PCmpEqD => a.pcmpeqd(xmm0, xmm1)?,
                VecOp::PAddPS => a.addps(xmm0, xmm1)?,
                VecOp::PMulPS => a.mulps(xmm0, xmm1)?,
                VecOp::PAddPD => a.addpd(xmm0, xmm1)?,
                VecOp::PShufD(imm) => a.pshufd(xmm0, xmm1, imm as i32)?,
                VecOp::Punpcklqdq => a.punpcklqdq(xmm0, xmm1)?,
            }
            a.pextrq(rax, xmm0, 0)?;
            a.mov(qword_ptr(rcx + 32i32), rax)?;
            a.pextrq(rax, xmm0, 1)?;
            a.mov(qword_ptr(rcx + 40i32), rax)?;
            a.ret()
        })
    }

    fn plain_atomic(op: AtomicOpIr, width: u8) -> Vec<u8> {
        asm_code(|a| {
            a.mov(rax, qword_ptr(rcx + 16i32))?; // expect
            a.mov(rdx, qword_ptr(rcx + 8i32))?; // incoming
            a.xor(r8d, r8d)?; // zf slot BEFORE any flag producer
            let m8 = byte_ptr(rcx);
            let m16 = word_ptr(rcx);
            let m32 = dword_ptr(rcx);
            let m64 = qword_ptr(rcx);
            match op {
                AtomicOpIr::CmpXchg => {
                    let _ = a.lock();
                    match width {
                        1 => a.cmpxchg(m8, dl)?,
                        2 => a.cmpxchg(m16, dx)?,
                        4 => a.cmpxchg(m32, edx)?,
                        _ => a.cmpxchg(m64, rdx)?,
                    }
                    let mut l_z = a.create_label();
                    a.mov(qword_ptr(rcx + 24i32), rax)?;
                    a.jne(l_z)?;
                    a.mov(r8d, 1u32)?;
                    a.set_label(&mut l_z)?;
                    a.mov(byte_ptr(rcx + 32i32), r8b)?;
                    a.ret()?;
                    Ok(())
                }
                AtomicOpIr::XAdd => {
                    // Mirror the IR: dst receives the register after the RMW
                    // (xadd leaves the old memory value in the source reg).
                    let _ = a.lock();
                    match width {
                        1 => a.xadd(m8, dl)?,
                        2 => a.xadd(m16, dx)?,
                        4 => a.xadd(m32, edx)?,
                        _ => a.xadd(m64, rdx)?,
                    }
                    a.mov(qword_ptr(rcx + 24i32), rdx)?;
                    a.mov(byte_ptr(rcx + 32i32), r8b)?;
                    a.ret()?;
                    Ok(())
                }
                AtomicOpIr::Xchg => {
                    match width {
                        1 => a.xchg(m8, dl)?,
                        2 => a.xchg(m16, dx)?,
                        4 => a.xchg(m32, edx)?,
                        _ => a.xchg(m64, rdx)?,
                    }
                    a.mov(qword_ptr(rcx + 24i32), rdx)?;
                    a.mov(byte_ptr(rcx + 32i32), r8b)?;
                    a.ret()?;
                    Ok(())
                }
            }
        })
    }

    // ------------------------------------------------------------------
    // Test drivers.
    // ------------------------------------------------------------------
    fn drive_scalar_f32() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_0001);
        let ops = [
            FOp::Add,
            FOp::Sub,
            FOp::Mul,
            FOp::Div,
            FOp::Min,
            FOp::Max,
            FOp::Sqrt,
        ];
        let edges = f32_edges();
        let mut cases = 0;
        for op in ops {
            for i in 0..edges.len() {
                for j in 0..edges.len() {
                    let mut buf = vec![0u8; 24];
                    buf[..4].copy_from_slice(&edges[i].to_le_bytes());
                    buf[8..12].copy_from_slice(&edges[j].to_le_bytes());
                    let name = format!("f32 {op:?} {:#x},{:#x}", edges[i], edges[j]);
                    assert_three_way(&name, &fscalar_ir(op, FWidth::F32), plain_f32(op), &mut buf, 16, 4);
                    cases += 1;
                }
            }
            for _ in 0..24 {
                let mut buf = vec![0u8; 24];
                buf[..4].copy_from_slice(&(rng.next() as u32).to_le_bytes());
                buf[8..12].copy_from_slice(&(rng.next() as u32).to_le_bytes());
                assert_three_way("f32 rand", &fscalar_ir(op, FWidth::F32), plain_f32(op), &mut buf, 16, 4);
                cases += 1;
            }
        }
        eprintln!("f32 scalar: {cases} three-way cases");
    }

    fn drive_scalar_f64() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_0002);
        let ops = [FOp::Add, FOp::Sub, FOp::Mul, FOp::Div, FOp::Min, FOp::Max, FOp::Sqrt];
        let edges = f64_edges();
        let mut cases = 0;
        for op in ops {
            for i in 0..edges.len() {
                for j in 0..edges.len() {
                    let mut buf = vec![0u8; 24];
                    buf[..8].copy_from_slice(&edges[i].to_le_bytes());
                    buf[8..16].copy_from_slice(&edges[j].to_le_bytes());
                    let name = format!("f64 {op:?}");
                    assert_three_way(&name, &fscalar_ir(op, FWidth::F64), plain_f64(op), &mut buf, 16, 8);
                    cases += 1;
                }
            }
            for _ in 0..24 {
                let mut buf = vec![0u8; 24];
                buf[..8].copy_from_slice(&rng.next().to_le_bytes());
                buf[8..16].copy_from_slice(&rng.next().to_le_bytes());
                assert_three_way("f64 rand", &fscalar_ir(op, FWidth::F64), plain_f64(op), &mut buf, 16, 8);
                cases += 1;
            }
        }
        eprintln!("f64 scalar: {cases} three-way cases");
    }

    fn drive_x87() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_0003);
        let ops = [FOp::Add, FOp::Sub, FOp::Mul, FOp::Div, FOp::Sqrt];
        let edges = f64_edges();
        let mut cases = 0;
        for op in ops {
            for i in 0..edges.len() {
                for j in 0..edges.len() {
                    let mut buf = vec![0u8; 24];
                    buf[..8].copy_from_slice(&edges[i].to_le_bytes());
                    buf[8..16].copy_from_slice(&edges[j].to_le_bytes());
                    let name = format!("x87 {op:?} {:#x},{:#x}", edges[i], edges[j]);
                    assert_three_way(&name, &fscalar_ir(op, FWidth::X87), plain_x87(op), &mut buf, 16, 8);
                    cases += 1;
                }
            }
            for _ in 0..24 {
                let mut buf = vec![0u8; 24];
                buf[..8].copy_from_slice(&rng.next().to_le_bytes());
                buf[8..16].copy_from_slice(&rng.next().to_le_bytes());
                assert_three_way("x87 rand", &fscalar_ir(op, FWidth::X87), plain_x87(op), &mut buf, 16, 8);
                cases += 1;
            }
        }
        eprintln!("x87: {cases} three-way cases");
    }

    fn drive_fcvt() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_0004);
        let kinds = [
            CvtKind::I32F32,
            CvtKind::I32F64,
            CvtKind::I64F32,
            CvtKind::I64F64,
            CvtKind::F32I32T,
            CvtKind::F64I32T,
            CvtKind::F32I64T,
            CvtKind::F64I64T,
            CvtKind::F32I32R,
            CvtKind::F64I64R,
            CvtKind::F32F64,
            CvtKind::F64F32,
        ];
        let mut inputs: Vec<u64> = Vec::new();
        inputs.extend([0u64, 1, 0xFFFF_FFFF, 0x8000_0000, 0x7FFF_FFFF, i64::MIN as u64, i64::MAX as u64, 42]);
        inputs.extend(f32_edges().iter().map(|v| *v as u64));
        inputs.extend(f64_edges());
        let mut cases = 0;
        for kind in kinds {
            // 32-bit results compare a 4-byte window; 64-bit compare 8.
            let w = match kind {
                CvtKind::I32F32
                | CvtKind::I64F32
                | CvtKind::F32I32T
                | CvtKind::F64I32T
                | CvtKind::F32I32R
                | CvtKind::F64F32 => 4usize,
                _ => 8,
            };
            for &v in &inputs {
                let mut buf = vec![0u8; 24];
                buf[..8].copy_from_slice(&v.to_le_bytes());
                let name = format!("cvt {kind:?} {v:#x}");
                assert_three_way(&name, &fcvt_ir(kind), plain_fcvt(kind), &mut buf, 16, w);
                cases += 1;
            }
            for _ in 0..16 {
                let v = rng.next();
                let mut buf = vec![0u8; 24];
                buf[..8].copy_from_slice(&v.to_le_bytes());
                assert_three_way("cvt rand", &fcvt_ir(kind), plain_fcvt(kind), &mut buf, 16, w);
                cases += 1;
            }
        }
        eprintln!("cvt: {cases} three-way cases");
    }

    fn drive_fcmp() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_0005);
        let edges32 = f32_edges();
        let edges64 = f64_edges();
        let mut cases = 0;
        for i in 0..edges32.len() {
            for j in 0..edges32.len() {
                let mut buf = vec![0u8; 24];
                buf[..4].copy_from_slice(&edges32[i].to_le_bytes());
                buf[8..12].copy_from_slice(&edges32[j].to_le_bytes());
                assert_three_way("fcmp32", &fcmp_ir(FWidth::F32), plain_fcmp(FWidth::F32), &mut buf, 16, 8);
                cases += 1;
            }
        }
        for i in 0..edges64.len() {
            for j in 0..edges64.len() {
                let mut buf = vec![0u8; 24];
                buf[..8].copy_from_slice(&edges64[i].to_le_bytes());
                buf[8..16].copy_from_slice(&edges64[j].to_le_bytes());
                assert_three_way("fcmp64", &fcmp_ir(FWidth::F64), plain_fcmp(FWidth::F64), &mut buf, 16, 8);
                cases += 1;
            }
        }
        for _ in 0..32 {
            let mut buf = vec![0u8; 24];
            let a = rng.next();
            let b = if cases % 2 == 0 { a } else { rng.next() };
            buf[..8].copy_from_slice(&a.to_le_bytes());
            buf[8..16].copy_from_slice(&b.to_le_bytes());
            assert_three_way("fcmp rand", &fcmp_ir(FWidth::F64), plain_fcmp(FWidth::F64), &mut buf, 16, 8);
            cases += 1;
        }
        eprintln!("fcmp: {cases} three-way cases");
    }

    fn drive_vec() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_0006);
        let ops = [
            VecOp::PAddD,
            VecOp::PSubD,
            VecOp::PMulLW,
            VecOp::PMulHW,
            VecOp::PMulLD,
            VecOp::PMinSD,
            VecOp::PMaxSD,
            VecOp::PAnd,
            VecOp::POr,
            VecOp::PXor,
            VecOp::PCmpEqD,
            VecOp::PAddPS,
            VecOp::PMulPS,
            VecOp::PAddPD,
            VecOp::PShufD(0b00_01_10_11),
            VecOp::Punpcklqdq,
        ];
        let mut cases = 0;
        for op in ops {
            for _ in 0..48 {
                let mut buf = vec![0u8; 48];
                for b in buf[..32].iter_mut() {
                    *b = rng.next() as u8;
                }
                // sprinkle recognizable lanes for eq/cmp coverage
                if cases % 4 == 0 {
                    let head: Vec<u8> = buf[0..8].to_vec();
                    buf[16..24].copy_from_slice(&head);
                }
                assert_three_way("vec", &vec_ir(op), plain_vec(op), &mut buf, 32, 16);
                cases += 1;
            }
        }
        eprintln!("vec: {cases} three-way cases");
    }

    fn drive_atomics() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_0007);
        let mut cases = 0;
        for &(op, width) in &[
            (AtomicOpIr::CmpXchg, 1u8),
            (AtomicOpIr::CmpXchg, 2),
            (AtomicOpIr::CmpXchg, 4),
            (AtomicOpIr::CmpXchg, 8),
            (AtomicOpIr::XAdd, 4),
            (AtomicOpIr::XAdd, 8),
            (AtomicOpIr::Xchg, 4),
            (AtomicOpIr::Xchg, 8),
        ] {
            for k in 0..64 {
                let mut buf = vec![0u8; 48];
                let mem0 = rng.next();
                let inc = rng.next();
                buf[..8].copy_from_slice(&mem0.to_le_bytes());
                buf[8..16].copy_from_slice(&inc.to_le_bytes());
                // Half the cases: expect matches memory (cmpxchg succeeds).
                let expect = if k % 2 == 0 { mem0 } else { rng.next() };
                buf[16..24].copy_from_slice(&expect.to_le_bytes());
                let name = format!("atomic {op:?} w{width} k{k}");
                assert_three_way(&name, &atomic_ir(op, width), plain_atomic(op, width), &mut buf, 0, 48);
                cases += 1;
            }
        }
        eprintln!("atomics: {cases} three-way cases");
    }

    // ------------------------------------------------------------------
    // Integer breadth (imul / shifts / neg / not / inc / dec paths).
    // These ops are 32-bit by contract, so the oracle runs at B32 with a
    // low base pointer (a high base would truncate under the 32-bit mask).
    // Layout: L@0, H@4, D@8 — all 4-byte.
    // ------------------------------------------------------------------
    const ORACLE_BASE32: u64 = 0x0002_0000;

    fn scalar32_ir(stmt: Stmt) -> IrModule {
        IrModule {
            entry: 0,
            blocks: vec![IrBlock {
                stmts: vec![
                    Stmt::Load { dst: L, addr: addr(0), width: 4 },
                    Stmt::Load { dst: H, addr: addr(4), width: 4 },
                    stmt,
                    Stmt::Store { addr: addr(8), src: Src::Reg(D), width: 4 },
                ],
                term: Term::Ret,
            }],
        }
    }

    fn oracle_run32(ir: &IrModule, buf: &mut [u8], out_off: usize, out_len: usize) -> Vec<u8> {
        let mut st = MachineState::new(Abi::Win64);
        st.width = xenolith_vm::semantics::Width::B32;
        st.gpr[B as usize] = ORACLE_BASE32;
        st.mem.write_bytes(ORACLE_BASE32, buf).unwrap();
        let _ = xenolith_vm::semantics::eval_machine(ir, &mut st).expect("oracle eval");
        st.mem.read_bytes(ORACLE_BASE32 + out_off as u64, out_len).unwrap()
    }

    fn assert_three_way32(
        name: &str,
        ir: &IrModule,
        plain: Vec<u8>,
        buf: &mut [u8],
        out_off: usize,
        out_len: usize,
    ) {
        let mut b2 = buf.to_vec();
        let mut b3 = buf.to_vec();
        let o = oracle_run32(ir, &mut b2, out_off, out_len);
        let s = superop_run(ir, &mut b3, out_off, out_len);
        let p = plain_run(plain, buf, out_off, out_len);
        assert_eq!(p, o, "{name}: plain != oracle");
        assert_eq!(s, o, "{name}: superop != oracle");
    }

    /// Raw-hardware reference for `D = L <op> H`. The buffer pointer is moved
    /// out of RCX so the shift-by-CL forms may clobber CL freely.
    fn plain_bin_rr(op: BinOp) -> Vec<u8> {
        asm_code(|a| {
            a.mov(r8, rcx)?;
            a.mov(eax, dword_ptr(r8))?;
            a.mov(edx, dword_ptr(r8 + 4i32))?;
            match op {
                BinOp::Add => a.add(eax, edx)?,
                BinOp::Sub => a.sub(eax, edx)?,
                BinOp::Xor => a.xor(eax, edx)?,
                BinOp::And => a.and(eax, edx)?,
                BinOp::Or => a.or(eax, edx)?,
                BinOp::Mul => a.imul_2(eax, edx)?,
                BinOp::Shl => {
                    a.mov(cl, dl)?;
                    a.shl(eax, cl)?;
                }
                BinOp::Shr => {
                    a.mov(cl, dl)?;
                    a.shr(eax, cl)?;
                }
                BinOp::Sar => {
                    a.mov(cl, dl)?;
                    a.sar(eax, cl)?;
                }
            }
            a.mov(dword_ptr(r8 + 8i32), eax)?;
            a.ret()
        })
    }

    /// Raw-hardware reference for `D = L <op> imm`.
    fn plain_bin_ri(op: BinOp, imm: u32) -> Vec<u8> {
        asm_code(|a| {
            a.mov(r8, rcx)?;
            a.mov(eax, dword_ptr(r8))?;
            match op {
                BinOp::Add => a.add(eax, imm)?,
                BinOp::Sub => a.sub(eax, imm)?,
                BinOp::Xor => a.xor(eax, imm)?,
                BinOp::And => a.and(eax, imm)?,
                BinOp::Or => a.or(eax, imm)?,
                BinOp::Mul => a.imul_3(eax, eax, imm as i32)?,
                BinOp::Shl => a.shl(eax, imm & 0x1f)?,
                BinOp::Shr => a.shr(eax, imm & 0x1f)?,
                BinOp::Sar => a.sar(eax, imm & 0x1f)?,
            }
            a.mov(dword_ptr(r8 + 8i32), eax)?;
            a.ret()
        })
    }

    fn drive_int32() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_0008);
        let ops = [
            BinOp::Add,
            BinOp::Sub,
            BinOp::Xor,
            BinOp::And,
            BinOp::Or,
            BinOp::Mul,
            BinOp::Shl,
            BinOp::Shr,
            BinOp::Sar,
        ];
        let vals: [u32; 17] = [
            0,
            1,
            2,
            3,
            7,
            8,
            31,
            32,
            33,
            0x7FFF_FFFF,
            0x8000_0000,
            0x8000_0001,
            0xFFFF_FFFE,
            0xFFFF_FFFF,
            0x1234_5678,
            0x9E37_79B9,
            0x0F0F_0F0F,
        ];
        let imms: [u32; 14] = [
            0,
            1,
            2,
            5,
            15,
            31,
            32,
            33,
            0xFF,
            0x100,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFF,
            0x9E37_79B9,
        ];
        let mut cases = 0;
        for op in ops {
            for &l in &vals {
                for &h in &vals {
                    let mut buf = vec![0u8; 16];
                    buf[0..4].copy_from_slice(&l.to_le_bytes());
                    buf[4..8].copy_from_slice(&h.to_le_bytes());
                    let ir = scalar32_ir(Stmt::Bin { op, dst: D, lhs: Src::Reg(L), rhs: Src::Reg(H) });
                    let name = format!("i32 rr {op:?} {l:#x},{h:#x}");
                    assert_three_way32(&name, &ir, plain_bin_rr(op), &mut buf, 8, 4);
                    cases += 1;
                }
            }
            for _ in 0..32 {
                let l = rng.next() as u32;
                let h = rng.next() as u32;
                let mut buf = vec![0u8; 16];
                buf[0..4].copy_from_slice(&l.to_le_bytes());
                buf[4..8].copy_from_slice(&h.to_le_bytes());
                let ir = scalar32_ir(Stmt::Bin { op, dst: D, lhs: Src::Reg(L), rhs: Src::Reg(H) });
                assert_three_way32("i32 rr rand", &ir, plain_bin_rr(op), &mut buf, 8, 4);
                cases += 1;
            }
            for &l in &vals {
                for &imm in &imms {
                    let mut buf = vec![0u8; 16];
                    buf[0..4].copy_from_slice(&l.to_le_bytes());
                    let ir = scalar32_ir(Stmt::Bin { op, dst: D, lhs: Src::Reg(L), rhs: Src::Imm(imm) });
                    let name = format!("i32 ri {op:?} {l:#x},{imm:#x}");
                    assert_three_way32(&name, &ir, plain_bin_ri(op, imm), &mut buf, 8, 4);
                    cases += 1;
                }
            }
        }
        eprintln!("i32: {cases} three-way cases");
    }

    #[test]
    fn int32_three_way() {
        drive_int32();
    }

    #[test]
    fn f32_scalar_three_way() {
        drive_scalar_f32();
    }

    #[test]
    fn f64_scalar_three_way() {
        drive_scalar_f64();
    }

    #[test]
    fn x87_three_way() {
        drive_x87();
    }

    #[test]
    fn fcvt_three_way() {
        drive_fcvt();
    }

    #[test]
    fn fcmp_three_way() {
        drive_fcmp();
    }

    #[test]
    fn vec_three_way() {
        drive_vec();
    }

    #[test]
    fn atomics_three_way() {
        drive_atomics();
    }
}
