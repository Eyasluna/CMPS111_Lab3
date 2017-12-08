/* 
 * This file is derived from source code for the Pintos
 * instructional operating system which is itself derived
 * from the Nachos instructional operating system. The 
 * Nachos copyright notice is reproduced in full below. 
 *
 * Copyright (C) 1992-1996 The Regents of the University of California.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose, without fee, and
 * without written agreement is hereby granted, provided that the
 * above copyright notice and the following two paragraphs appear
 * in all copies of this software.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
 * ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
 * AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
 * HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
 * BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 *
 * Modifications Copyright (C) 2017 David C. Harrison. All rights reserved.
 */

#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>

#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/umem.h"

static void syscall_handler(struct intr_frame *);

static void write_handler(struct intr_frame *);
static void exit_handler(struct intr_frame *);
static void create_handler(struct intr_frame *);
static void open_handler(struct intr_frame *);
static void read_handler(struct intr_frame *);
static void filesize_handler(struct intr_frame *);
static void close_handler(struct intr_frame *);
static void exec_handler(struct intr_frame *);
struct file *fdtofile(int fd);
struct file *fdtofilepop(int fd);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  int syscall;
  ASSERT( sizeof(syscall) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  umem_read(f->esp, &syscall, sizeof(syscall));
  //printf("syscall handling %i\n",syscall);

  // Store the stack pointer esp, which is needed in the page fault handler.
  // Do NOT remove this line
  thread_current()->current_esp = f->esp;

  switch (syscall) {
  case SYS_HALT: 
    shutdown_power_off();
    break;

  case SYS_EXIT: 
    exit_handler(f);
    break;
  
  case SYS_EXEC:
    exec_handler(f);
    break;
  
  case SYS_WRITE: 
    write_handler(f);
    break;
    
  case SYS_CREATE:
      create_handler(f);
      break;
      
  case SYS_OPEN:
      open_handler(f);
      break;
      
  case SYS_FILESIZE:
      filesize_handler(f);
      break;
      
  case SYS_READ:
      read_handler(f);
      break;
      
  case SYS_CLOSE:
      close_handler(f);
      break;
      
  default:
    printf("[ERROR] system call %d is unimplemented!\n", syscall);
    thread_exit();
    break;
  }
}

/****************** System Call Implementations ********************/

// *****************************************************************
// CMPS111 Lab 3 : Put your new system call implementatons in your 
// own source file. Define them in your header file and include 
// that .h in this .c file.
// *****************************************************************

void sys_exit(int status) 
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

static void exit_handler(struct intr_frame *f) 
{
  int exitcode;
  umem_read(f->esp + 4, &exitcode, sizeof(exitcode));

  sys_exit(exitcode);
}

/*
 * BUFFER+0 and BUFFER+size should be valid user adresses
 */
static uint32_t sys_write(int fd, const void *buffer, unsigned size)
{
   // printf("fd=%i",fd);
  umem_check((const uint8_t*) buffer);
  umem_check((const uint8_t*) buffer + size - 1);

  int ret = -1;

  if (fd == 1) { // write to stdout
    putbuf(buffer, size);
    ret = size;
  }
  else
  {
      struct file *temp=fdtofile(fd);
      ret=file_write(temp,buffer,size);
  }
  
  return (uint32_t) ret;
}

static void write_handler(struct intr_frame *f)
{
    int fd;
    const void *buffer;
    unsigned size;

    umem_read(f->esp + 4, &fd, sizeof(fd));
    umem_read(f->esp + 8, &buffer, sizeof(buffer));
    umem_read(f->esp + 12, &size, sizeof(size));

    f->eax = sys_write(fd, buffer, size);
}

static void create_handler(struct intr_frame *f)
{
    unsigned initial_size;
    const char *file;
    umem_read(f->esp+4,&file,sizeof(file));
    umem_read(f->esp+8,&initial_size,sizeof(initial_size));
    f->eax=filesys_create(file,initial_size,false);
}
static void open_handler(struct intr_frame *f)
{
    const char *file;
    umem_read(f->esp+4,&file,sizeof(file));
   
    struct file *openedfile=filesys_open(file);
 //    printf("file=%u\n",openedfile);
    if(!openedfile)
        f->eax=-1;
    else
    {
        addfiletolist(openedfile,f->eax);
    }
  /*  if(!openedfile)
    {
        unsigned num=malloc(sizeof(unsigned));
        filesys_create(file,&num,false);
        filesys_open(file);
        
    }*/
   // struct inode *inodetemp=openedfile->inode;
    
   // f->eax=openedfile;
    
}

static void read_handler(struct intr_frame *f)
{
    int fd;
    void *buffer;
    unsigned size;
    umem_read(f->esp + 4, &fd, sizeof(fd));
    umem_read(f->esp + 8, &buffer, sizeof(buffer));
    umem_read(f->esp + 12, &size, sizeof(size));
    struct file *targetfile=fdtofile(fd);
    //printf("fileaddress=%u buffer=%u size=%u\n",targetfile,buffer,size);
    f->eax=file_read(targetfile,buffer,size);

    
}


static void filesize_handler(struct intr_frame *f)
{
    int fd;
    umem_read(f->esp + 4, &fd, sizeof(fd));
   // printf("looking for %i\n",fd);
    struct file *targetfile=fdtofile(fd);
    f->eax=file_length(targetfile);
}

static void close_handler(struct intr_frame *f)
{
    int fd;
    umem_read(f->esp+4,&fd,sizeof(fd));
    struct file *targetfile=fdtofilepop(fd);
    file_close(targetfile);
}

static void exec_handler(struct intr_frame *f)
{
    const char *file;
    umem_read(f->esp+4,&file,sizeof(file));
    //printf("cmdline=%s",file);
    tid_t pid=process_execute(file);
    //barrier();
    //timer_msleep(1000);
    f->eax=pid;

}

void addfiletolist(struct file *file,int fd)
{
  //  printf("adding fd=%i to list\n",fd);
    struct filefd *newfilefd=malloc(sizeof(struct filefd));
    newfilefd->fd=fd;
   // printf("file=%u",file);
    newfilefd->targetfile=file;
    list_push_back(&thread_current()->filelist,&newfilefd->elem);
}
struct file *fdtofile(int fd)
{
    //struct list *boobies=&thread_current()->filelist;
    struct list_elem *e;
    for(e= list_begin(&thread_current()->filelist);
        e!=list_end(&thread_current()->filelist);
        e=list_next(e)
        )
    {
        struct filefd *temp=list_entry(e,struct filefd, elem);
        if(temp->fd==fd)
        {
            return temp->targetfile;
        }
    }
    return NULL;
}
struct file *fdtofilepop(int fd)
{
        //struct list *boobies=&thread_current()->filelist;
    struct list_elem *e;
    for(e= list_begin(&thread_current()->filelist);
        e!=list_end(&thread_current()->filelist);
        e=list_next(e)
        )
    {
        struct filefd *temp=list_entry(e,struct filefd, elem);
        if(temp->fd==fd)
        {
            struct file* temp2=temp->targetfile;
            list_remove(e);
            return temp2;
        }
    }
    return NULL;
}