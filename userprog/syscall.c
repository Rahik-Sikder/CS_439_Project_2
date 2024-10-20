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
  // Rahik start driving
  // Get the system call number from the stack
  // Jake start driving
  // Rahik start driving
  int *sp = (int *) f->esp;
  int syscall_number = *sp;
  sp++;
  // Rahik end driving

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
        // MIlan start driving
        int status = *sp;
        struct thread *cur = thread_current (); // Get current thread/process
        cur->exit_status = status;              // Set exit status
        thread_exit ();
        // Milan stop driving
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
        // Rahik start driving
        const char *file =  *(char *)((char*)f->esp + 4);  
        unsigned initial_size = *(unsigned *)((char*)f->esp + 8); 

        if (file == NULL || !is_user_vaddr(file) || strlen(file) == 0) {
            f->eax = false;  
        } else {
            int status = filesys_create(file, initial_size);
            f->eax = status; 
        }
        // Rahik end driving
        break;
      case SYS_REMOVE: /* Delete a file. */
        // Milan start driving
        const char *file =  *(char *)((char*)f->esp + 4);  
        if (file == NULL || !is_user_vaddr(file) || strlen(file) == 0) {
            f->eax = -1;
        }
        else{
            f->eax = filesys_remove(file);
        }
        break;
      case SYS_OPEN: /* Open a file. */
        const char *file =  *(char *)((char*)f->esp + 4);  
        if (file == NULL || !is_user_vaddr(file) || strlen(file) == 0) {
            f->eax = -1;
        }
        else{
            f->eax = filesys_open(file);
        }
        // Milan end driving
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