#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
bool validate_user_address(const void *addr);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void syscall_handler (struct intr_frame *f) {
    // Get the system call number from the stack

    int syscall_number = *(int*)f->esp; 

    if(!validate_user_address(f->esp)){
      return;
    }

    switch (syscall_number) {
        case SYS_EXEC:
            printf("printing f->esp\n");
            printf("%s\n",f->esp);
            printf("printing f->esp + 4\n");
            printf("%s\n",(char *)((char *)f->esp + 4));
            printf("exec hex dump\n");
            hex_dump(f->esp, f->esp, 128, 1);
            break;
        case SYS_HALT:
            shutdown_power_off();
            break;
        case SYS_EXIT:
            int status = *(int *)(((char*)f->esp) + 4); 
            struct thread *cur = thread_current();  // Get current thread/process
            cur->exit_status = status;              // Set exit status
            thread_exit();
            break;
    }
}

bool validate_user_address(const void *addr) {
    if (addr == NULL || !is_user_vaddr(addr) || pagedir_get_page(thread_current()->pagedir, addr) == NULL) {
        return false;
    }
    return true;
}