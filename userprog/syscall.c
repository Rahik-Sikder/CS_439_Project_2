#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

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
  char *file;
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
        char *cmd_line = *(char *) (sp++);
        struct semaphore exec_sema;
        sema_init (&exec_sema, 0);
        // Guide says there's a possible error here with this code apparently
        // returning b4 exec finishes loading the child -> don't really see
        // how it could given the current implementation but who knows
        tid_t result = process_execute (cmd_line);
        return result;
        break;
      case SYS_WAIT: /* Wait for a child process to die. */
        tid_t child = *(tid_t *) sp++;
        return process_wait (child);
        break;
      case SYS_CREATE: /* Create a file. */
        *file = (char *) *(sp++);
        unsigned initial_size = *(unsigned *) (sp++);

        if (file == NULL || !is_user_vaddr (file) || strlen (file) == 0)
          {
            f->eax = false;
          }
        else
          {
            int status = filesys_create (file, initial_size);
            f->eax = status;
          }
        break;
      case SYS_REMOVE: /* Delete a file. */
        *file = (char *) *(sp++);
        if (file == NULL || !is_user_vaddr (file) || strlen (file) == 0)
          {
            f->eax = -1;
          }
        else
          {
            f->eax = filesys_remove (file);
          }
        break;
      case SYS_OPEN: /* Open a file. */
        *file = (char *) *(sp++);
        if (file == NULL || !is_user_vaddr (file) || strlen (file) == 0)
          {
            f->eax = -1;
          }
        else
          {
            f->eax = filesys_open (file);
          }
        break;
      case SYS_FILESIZE: /* Obtain a file's size. */
        break;
      case SYS_READ: /* Read from a file. */
        break;
      case SYS_WRITE: /* Write to a file. */
        int fd = *(sp++);
        char *buffer = (char *) *(sp++);
        unsigned size = (unsigned) *(sp++);
        if (fd == 1)
          {
            putbuf (buffer, size);
            return size; // this return is needed -> should investigate more
          }
        else
          {
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