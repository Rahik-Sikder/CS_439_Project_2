#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
// static void halt_hander (struct intr_frame *f UNUSED);
// static void exit_handler (struct intr_frame *f UNUSED);

void syscall_init (void)
{
  // intr_register_int (0x0, 0, INTR_ON, halt_hander, "halt");
  // intr_register_int (0x1, 3, INTR_ON, exit_handler, "exit");
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  if(f->vec_no==0){
    shutdown_power_off();
  }
  else if (f->vec_no==1){
    process_exit();
    return 0;
  }
}

static void halt_hander (struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}

static void exit_handler (struct intr_frame *f UNUSED)
{
  process_exit();
  return 0;
}

// static void exec_handler (struct intr_frame *f UNUSED)
// {
//   process_exit();
// }
