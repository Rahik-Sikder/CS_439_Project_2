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
  // Rahik start driving
  // Get the system call number from the stack
  // Jake start driving
  // Rahik start driving
  int *sp = (int *) f->esp;
  // Rahik start driving
  int syscall_number;
  if (!validate_user_address (sp))
    {
      int status = -1;
      struct thread *cur = thread_current (); // Get current thread/process
      cur->exit_status = status;              // Set exit status
      printf ("%s: exit(%d)\n", cur->name, cur->exit_status);
      thread_exit ();
      return;
    }
  else
    {
      syscall_number = *sp;
      sp++;
    }
  // Rahik end driving
  // Rahik end driving

  char *file;
  switch (syscall_number)
    {
      case SYS_HALT:
        shutdown_power_off ();
        break;
      case SYS_EXIT:
        // MIlan start driving
        int status = *sp;
        // Rahik start driving
        if (status < -1)
          status = -1;
        struct thread *cur = thread_current (); // Get current thread/process
        cur->exit_status = status;              // Set exit status
        printf ("%s: exit(%d)\n", cur->name, cur->exit_status);
        // Rahik end driving
        thread_exit ();
        // Milan stop driving
        break;
      case SYS_EXEC:
        // Jake start driving
        char *cmd_line = *(char *) (sp++);
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
        // Rahik start driving
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
        // Rahik end driving
        break;
      case SYS_REMOVE: /* Delete a file. */
        // Milan start driving
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
        // Milan end driving
        break;
      case SYS_FILESIZE: /* Obtain a file's size. */
        break;
      case SYS_READ: /* Read from a file. */
        break;
      case SYS_WRITE: /* Write to a file. */
        int fd = *(sp++);
        char *buffer = (char *) *(sp++);
        unsigned size = (unsigned) *(sp++);
        // Jake end driving
        if (fd == 1)
          {
            putbuf (buffer, size);
            return size; // this return is needed -> should investigate more
          }
        else
          {
            // idk yet, we do this later
            printf ("file write, not yet implemented %d\n", syscall_number);
          }
        break;
      case SYS_SEEK: /* Change position in a file. */
        break;
      case SYS_TELL: /* Report current position in a file. */
        break;
      case SYS_CLOSE:
        break;
      default:
        printf ("system %d\n", syscall_number);
    }
    // Jake end driving
    // Rahik end driving
}

bool validate_user_address (const void *addr)
{
  // Jake start driving
  // Rahik start driving
  if (addr == NULL || !is_user_vaddr (addr) ||
      pagedir_get_page (thread_current ()->pagedir, addr) == NULL)
    {
      return false;
    }
  return true;
  // Rahik end driving
  // Jake end driving
}
