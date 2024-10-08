#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
bool validate_user_address (const void *addr);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void syscall_handler (struct intr_frame *f)
{

  // Get the system call number from the stack
  int *sp = (int *) f->esp;
  int syscall_number = *sp;
  sp++;

  if (!validate_user_address (f->esp))
    {
      return;
    }

  switch (syscall_number)
    {
      case SYS_HALT:
        shutdown_power_off ();
        break;
      case SYS_EXIT:
        int status = *sp;
        struct thread *cur = thread_current (); // Get current thread/process
        cur->exit_status = status;              // Set exit status
        thread_exit ();
        break;
      case SYS_EXEC:
        // printf("system exec\n");
        // printf("printing f->esp\n");
        // printf("%s\n",f->esp);
        // printf("printing f->esp + 4\n");
        // printf("%s\n",(char *)((char *)f->esp + 4));
        // printf("exec hex dump\n");
        // hex_dump(f->esp, f->esp, 128, 1);
        break;
      case SYS_WAIT: /* Wait for a child process to die. */
        break;
      case SYS_CREATE: /* Create a file. */
        break;
      case SYS_REMOVE: /* Delete a file. */
        break;
      case SYS_OPEN: /* Open a file. */
        break;
      case SYS_FILESIZE: /* Obtain a file's size. */
        break;
      case SYS_READ: /* Read from a file. */
        break;
      case SYS_WRITE: /* Write to a file. */
        int fd = *sp;
        sp++;
        char *buffer = (char *) *sp;
        sp++;
        unsigned size = (unsigned) *sp;
        if (fd == 1)
          {
            putbuf (buffer, size);
            return size; // this return is needed -> should investigate more
          }
        else {
            // idk yet, we do this later
        }
        break;
      case SYS_SEEK: /* Change position in a file. */
        break;
      case SYS_TELL: /* Report current position in a file. */
        break;
      case SYS_CLOSE:
        break;
      default:
        // printf("system %d\n", syscall_number);
    }
}

bool validate_user_address (const void *addr)
{
  if (addr == NULL || !is_user_vaddr (addr) ||
      pagedir_get_page (thread_current ()->pagedir, addr) == NULL)
    {
      return false;
    }
  return true;
}