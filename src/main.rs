#![cfg_attr(feature = "kern", no_std, no_main, feature(lang_items))]
#![cfg_attr(feature = "kern", allow(unused))]

#[cfg(feature = "kern")]
use ebpf_kern as ebpf;
#[cfg(feature = "user")]
use ebpf_user as ebpf;

#[cfg(any(feature = "kern", feature = "user"))]
#[derive(ebpf::BpfApp)]
pub struct App {
    #[ringbuf(size = 0x10000)]
    pub event_queue: ebpf::RingBufferRef,
    #[prog("tracepoint/syscalls/sys_enter_execve")]
    pub execve: ebpf::ProgRef,
    #[prog("tracepoint/syscalls/sys_enter_execveat")]
    pub execveat: ebpf::ProgRef,
    #[hashmap(size = 0x1000)]
    pub pid: ebpf::HashMapRef<4, 4>,
    #[hashmap(size = 0x100)]
    pub context_parameters: ebpf::HashMapRef<4, 0x20>,
}

#[cfg(feature = "kern")]
impl App {
    #[inline(always)]
    pub fn syscall(&mut self, ctx: ebpf::Context) -> Result<(), i32> {
        let argv = ctx.read_here::<*const *const u8>(0x20);
        self.check_name(argv)
    }

    #[inline(always)]
    pub fn execve(&mut self, ctx: ebpf::Context) -> Result<(), i32> {
        self.syscall(ctx)
    }

    #[inline(always)]
    pub fn execveat(&mut self, ctx: ebpf::Context) -> Result<(), i32> {
        self.syscall(ctx)
    }

    #[inline(always)]
    fn check_name(&mut self, argv: *const *const u8) -> Result<(), i32> {
        use ebpf::helpers;

        if argv.is_null() {
            return Err(0);
        }

        let mut arg_str = self.event_queue.reserve(8)?;
        let c =
            unsafe { helpers::probe_read_user(arg_str.as_mut().as_mut_ptr() as _, 8, argv as _) };

        if c == 0 {
            let entry = unsafe { *(arg_str.as_ref().as_ptr() as *const *const u8) };
            arg_str.discard();

            if !entry.is_null() {
                let mut str_bytes = self.event_queue.reserve(0x200)?;
                unsafe {
                    helpers::probe_read_user_str(
                        str_bytes.as_mut().as_mut_ptr() as _,
                        0x200,
                        entry as _,
                    )
                };
                let _ = self.event_queue.output(str_bytes.as_ref());
                str_bytes.discard();
            }
        } else {
            arg_str.discard();
        }

        Err(0)
    }
}


#[cfg(feature="kern")]
#[panic_handler]
fn default_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(feature = "user")]
fn main() -> Result<(), i32> {
    use std::{time::Duration, mem::ManuallyDrop};
    use ebpf::{Skeleton, RingBufferRegistry};

    static CODE: &[u8] = include_bytes!(concat!("../", env!("BPF_CODE")));

    let mut skeleton = Skeleton::<App>::open("example-kprobe\0", CODE)?;
    skeleton.load()?;
    let (_skeleton, app) = skeleton.attach()?;

    let mut rb = RingBufferRegistry::default();
    let mut handler = |s: ManuallyDrop<Box<[u8]>>| {
        if let Ok(f) = String::from_utf8(s.to_vec()) {
            let f = f.trim();
            println!("{}", f);
        }
    };
    rb.add(&app.event_queue, &mut handler)?;

    loop {
        match rb.poll(Duration::from_millis(100)) {
            Ok(_) => (),
            Err(c) if c == -4 => break Ok(()),
            Err(c) => break Err(c),
        }
    }
}