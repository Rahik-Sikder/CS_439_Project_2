#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

bool validate_user_address (const void *addr);

static struct file *get_file_from_fd (int fd);
bool get_user_32bit (const void *src);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int syscall_error (struct intr_frame *f)
{
  int status = -1;
  struct thread *cur = thread_current (); // Get current thread/process
  cur->exit_status = status;              // Set exit status
  f->eax = status;
  thread_exit ();
  return -1;
}

void syscall_handler (struct intr_frame *f)
{

  // Get the system call number from the stack

  int *sp = (int *) f->esp;
  int syscall_number;
  if (!get_user_32bit (sp))
    return syscall_error (f);

  syscall_number = *sp;
  sp++;

  char *file;
  struct thread *cur = thread_current ();
  int fd;
  struct file *found_file;
  unsigned size;
  char *buffer;

  switch (syscall_number)
    {
      case SYS_HALT:
        shutdown_power_off ();
        break;

      case SYS_EXIT:
        int status = *(sp++);
        if (status < -1)
          status = -1;
        cur->exit_status = status; // Set exit status
        
        thread_exit ();
        break;

      case SYS_EXEC:
        char *cmd_line = (char *) *(sp++);
        if (!validate_user_address (cmd_line))
          return syscall_error (f);

        // Guide says there's a possible error here with this code apparently
        // returning b4 exec finishes loading the child -> don't really see
        // how it could given the current implementation but who knows
        tid_t result = process_execute (cmd_line);
        f->eax = result;
        break;

      case SYS_WAIT: /* Wait for a child process to die. */
        tid_t child = *(tid_t *) sp++;
        int exit_status = process_wait (child);
        f->eax = exit_status;
        return;
        break;

      case SYS_CREATE: /* Create a file. */
       // Get the file name and initial size from the stack
        char *file = (char *) *(sp++);
        unsigned initial_size = *(unsigned *) (sp++);

        // Check if the file pointer is NULL or an invalid user address
        if (!get_user_32bit(file) || file == NULL) {
            f->eax = 0; // Indicate failure
            cur->exit_status = -1;              // Set exit status
            
            thread_exit ();
        } else {
            // If the file name is an empty string, it should also fail
            if (strlen(file) == 0) {
                f->eax = 0; // File name is empty, indicate failure
                cur->exit_status = -1;              // Set exit status
                
                thread_exit ();
            } else {
                // Attempt to create the file
                bool success = filesys_create(file, initial_size);
                f->eax = success;
            }
        }
        break;

      case SYS_REMOVE: /* Delete a file. */
        file = (char *) *(sp++);
        if (file == NULL || !is_user_vaddr (file) || strlen (file) == 0)
          syscall_error (f);

        f->eax = filesys_remove (file);
        break;

      case SYS_OPEN: /* Open a file. */
        file = (char *) *(sp++);
        if (file == NULL || !is_user_vaddr (file) ){
          return syscall_error (f);
        }
        else if (strlen (file) == 0){
          int return_val = -1;
          struct thread *cur = thread_current (); // Get current thread/process
          cur->exit_status = return_val;              // Set exit status
          f->eax = (int) -1;
          return -1;
        }
          

        struct file *opened_file = filesys_open (file);
        if(opened_file==NULL){
          int return_val = -1;
          struct thread *cur = thread_current (); // Get current thread/process
          cur->exit_status = return_val;              // Set exit status
          f->eax = (int) -1;
          return -1;
        }

        struct file_descriptor *fd_entry =
            malloc (sizeof (struct file_descriptor));
        if (fd_entry == NULL)
          {
            file_close (opened_file);
            return syscall_error (f);
          }
        fd_entry->fd = cur->curr_fd;
        cur->curr_fd++;
        fd_entry->open_file = opened_file;
        list_push_back (&cur->file_descriptors, &fd_entry->file_elem);
        f->eax = fd_entry->fd;
        break;

      case SYS_FILESIZE: /* Obtain a file's size. */
        fd = *(sp++);
        found_file = get_file_from_fd (fd);

        if (found_file == NULL)
            return syscall_error (f);
            
        f->eax = file_length (found_file);
        break;

      case SYS_READ: /* Read from a file. */
        fd = *(sp++);
        buffer = (char *) *(sp++);
        size = (unsigned) *(sp++);
        if (!validate_user_address (buffer) ||
            !is_user_vaddr (buffer + size - 1))
            return syscall_error (f);
        
        if (fd == 0)
          {
            for (unsigned i = 0; i < size; i++)
              {
                buffer[i] = input_getc ();
              }
            f->eax = size;
          }
        else
          {
            found_file = get_file_from_fd (fd);

            if (found_file == NULL)
              {
                syscall_error (f);
                return;
              }

            f->eax = file_read (found_file, buffer, size);
          }
        break;

      case SYS_WRITE: /* Write to a file. */
        fd = *(sp++);
        buffer = (char *) *(sp++);
        size = (unsigned) *(sp++);
        if (!validate_user_address (buffer) ||
            !is_user_vaddr (buffer + size - 1))
          return syscall_error (f);

        if (fd == 1)
          {
            putbuf (buffer, size);
            f->eax = size;
          }
        else
          {
            struct file *file =
                get_file_from_fd (fd); // Retrieve the file using fd
            if (file == NULL)
              {
                syscall_error (f);
                return;
              }

            int bytes_written = file_write (file, buffer, size);
            f->eax = bytes_written;
          }
        break;

      case SYS_SEEK: /* Change position in a file. */
        fd = *(sp++);
        unsigned position = (unsigned) *(sp++);

        found_file = get_file_from_fd (fd);

        if (file == NULL)
          return syscall_error (f);

        file_seek (file, position);
        f->eax = 0;
        break;

      case SYS_TELL: /* Report current position in a file. */
        fd = *(sp++);
        found_file = get_file_from_fd (fd);
        if (file == NULL)
          return syscall_error (f);

        f->eax = file_tell (file);
        break;

      case SYS_CLOSE:
        fd = *(sp++);
        struct list_elem *e;

        for (e = list_begin (&cur->file_descriptors);
             e != list_end (&cur->file_descriptors); e = list_next (e))
          {
            struct file_descriptor *fd_entry =
                list_entry (e, struct file_descriptor, file_elem);

            if (fd_entry->fd == fd)
              {
                file_close (fd_entry->open_file); // Close the file
                list_remove (e); // Remove the entry from the fd_table
                free (fd_entry); // Free the memory for the file descriptor
                return;
              }
          }
        break;

      default:
        printf ("system %d\n", syscall_number);
    }
  return;
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

static struct file *get_file_from_fd (int fd)
{
  struct thread *cur = thread_current (); // Get current thread (process)
  struct list_elem *e;

  for (e = list_begin (&cur->file_descriptors);
       e != list_end (&cur->file_descriptors); e = list_next (e))
    {
      struct file_descriptor *fd_entry =
          list_entry (e, struct file_descriptor, file_elem);

      if (fd_entry->fd == fd)
        {
          return fd_entry->open_file;
        }
    }

  return NULL;
}
bool get_user_32bit (const void *src)
{
  /* Check that all 4 bytes of the source address are in valid user memory */
  for (int i = 0; i < sizeof (uint32_t); i++)
    {
      if (!validate_user_address ((uint8_t *) src + 1))
        {
          return false;
        }
    }
}
