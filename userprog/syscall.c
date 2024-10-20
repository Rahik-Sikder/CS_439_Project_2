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

void syscall_handler (struct intr_frame *f)
{
  // Rahik start driving
  // Get the system call number from the stack
  // Jake start driving
  // Rahik start driving
  int *sp = (int *) f->esp;
  // Rahik start driving
  int syscall_number;
  // Milan start driving
  if (!get_user_32bit (sp) || !validate_user_address (sp))
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
  // Milan start driving
  struct thread *cur = thread_current ();
  int fd;
  // Jake start driving
  struct file *found_file;
  unsigned size;
  char *buffer;
  // Jake end driving

  switch (syscall_number)
    {
      case SYS_HALT:
        shutdown_power_off ();
        break;
      case SYS_EXIT:
        // Milan start driving
        int status = *(sp++);
        // Rahik start driving

        if (status < -1)
          status = -1;
        cur->exit_status = status; // Set exit status
        // Milan end driving
        printf ("%s: exit(%d)\n", cur->name, cur->exit_status);
        // Rahik end driving
        thread_exit ();
        // Milan stop driving
        break;
      case SYS_EXEC:
        // Jake start driving
        // Rahik start driving
        // Milan start driving
        char *cmd_line = (char *) (sp++);
        // Guide says there's a possible error here with this code apparently
        // returning b4 exec finishes loading the child -> don't really see
        // how it could given the current implementation but who knows
        tid_t result = process_execute (cmd_line);
        f->eax = result;
        return;
        break;
      case SYS_WAIT: /* Wait for a child process to die. */
        tid_t child = *(tid_t *) sp++;
        // Jake start driving
        int exit_status = process_wait (child);
        f->eax = exit_status;
        return;
        break;
      case SYS_CREATE: /* Create a file. */
        // Rahik start driving
        file = (char *) *(sp++);
        unsigned initial_size = *(unsigned *) (sp++);
        if (file == NULL || !is_user_vaddr (file) || strlen (file) == 0 ||
            initial_size == 0)
          {
            f->eax = -1;
          }
        else
          {
            // printf("input string '%s' length of %d with initial size %d\n",
            // file, strlen (file), initial_size);
            int status = filesys_create (file, initial_size);
            f->eax = status;
          }
        // Rahik end driving
        break;
      case SYS_REMOVE: /* Delete a file. */
        // Milan start driving

        file = (char *) *(sp++);
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
        file = (char *) *(sp++);

        if (file == NULL || !is_user_vaddr (file) || strlen (file) == 0)
          {
            f->eax = -1;
          }
        else
          {
            // Milan start driving
            struct file *opened_file = filesys_open (file);
            struct file_descriptor *fd_entry =
                malloc (sizeof (struct file_descriptor));
            if (fd_entry == NULL)
              {
                file_close (opened_file);
                f->eax = -1;
              }
            fd_entry->fd = cur->curr_fd;
            cur->curr_fd++;
            fd_entry->open_file = opened_file;
            list_push_back (&cur->file_descriptors, &fd_entry->file_elem);
            f->eax = fd_entry->fd;
          }
        break;
      case SYS_FILESIZE: /* Obtain a file's size. */
        fd = *(sp++);
        // Jake start driving
        found_file = get_file_from_fd (fd);

        if (found_file == NULL)
          {
            f->eax = -1;
          }
        f->eax = file_length (file);
        break;
      case SYS_READ: /* Read from a file. */
        fd = *(sp++);
        buffer = (char *) *(sp++);
        size = (unsigned) *(sp++);

        if (!validate_user_address (buffer) ||
            !is_user_vaddr (buffer + size - 1))
          {
            f->eax = -1;
            return;
          }

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
            if (file == NULL)
              {
                f->eax = -1;
                return;
              }

            f->eax = file_read (file, buffer, size);
          }
        break;
      case SYS_WRITE: /* Write to a file. */
        fd = *(sp++);
        buffer = (char *) *(sp++);
        size = (unsigned) *(sp++);
        if (!validate_user_address (buffer) ||
            !is_user_vaddr (buffer + size - 1))
          {
            f->eax = -1;
            return;
          }
        if (fd == 1)
          {
            putbuf (buffer, size);
            f->eax = size;
            return;
            // Jake end driving
          }
        else
          {
            struct file *file =
                get_file_from_fd (fd); // Retrieve the file using fd

            if (file == NULL)
              {
                f->eax = -1; // Return error if file not found
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
          {
            f->eax = -1;
          }
        else
          {
            file_seek (file, position);
            f->eax = 0;
          }

        break;
      case SYS_TELL: /* Report current position in a file. */
        fd = *(sp++);
        found_file = get_file_from_fd (fd);
        if (file == NULL)
          {
            f->eax = -1;
          }
        else
          {
            f->eax = file_tell (file);
          }

        break;
      case SYS_CLOSE:
        fd = *(sp++);
        // Jake end driving
        // Milan end driving
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
        // Milan end driving
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

// Milan start driving
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
// Milan end driving
// Jake start driving
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
// Jake end driving
