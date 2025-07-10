//
// Starter code for CS 454/654
// You SHOULD change this file
//

#include "debug.h"
#include "rpc.h"
INIT_LOG

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include "rw_lock.h"

char *server_persist_dir = nullptr;

struct file_state {
    rw_lock_t *lock;
    bool open_for_write;
};

std::unordered_map<std::string, file_state> server_file_state;
rw_lock_t *state_lock;

std::string get_full_path(char *short_path) {
    std::string full_path(server_persist_dir);
    full_path.append(short_path);

    DLOG("Full path: %s\n", full_path.c_str());

    return full_path;
}


bool is_file_open(std::string full_path) {
    rw_lock_lock(state_lock, RW_READ_LOCK);
    bool ret = server_file_state.find(full_path) != server_file_state.end();
    rw_lock_unlock(state_lock, RW_READ_LOCK);
    return ret;
}

int watdfs_lock(int *argTypes, void **args) {
    char *short_path = (char *)args[0];
    rw_lock_mode_t *mode = (rw_lock_mode_t* )args[1];
    int *ret = (int*)args[2];

    DLOG("Locking file: %s with mode: %d", short_path, *mode);


    std::string full_path = get_full_path(short_path);
    rw_lock_lock(state_lock, RW_WRITE_LOCK);
    bool open_for_write = *mode == RW_WRITE_LOCK;
    if (server_file_state.find(full_path) == server_file_state.end()) {
        struct file_state new_state;
        new_state.lock = new rw_lock_t;
        rw_lock_init(new_state.lock);
        new_state.open_for_write = open_for_write;
        server_file_state[full_path] = new_state;
    }

    auto entry = server_file_state[full_path];
    entry.open_for_write = open_for_write;

    rw_lock_unlock(state_lock, RW_WRITE_LOCK);

    int lock_Ret = rw_lock_lock(entry.lock, *mode);
    if (lock_Ret < 0) {
        *ret = lock_Ret;
    } else {
        *ret = lock_Ret;
    }

    return 0;
}

int watdfs_unlock(int *argTypes, void **args) {
    char *short_path = (char *)args[0];
    rw_lock_mode_t *mode = (rw_lock_mode_t*)args[1];
    int *ret = (int *)args[2];

    std::string full_path = get_full_path(short_path);

    rw_lock_lock(state_lock, RW_WRITE_LOCK);
    auto entry = server_file_state[full_path];
    int unlock_Ret = rw_lock_unlock(entry.lock, *mode);
    rw_lock_unlock(state_lock, RW_WRITE_LOCK);

    if (unlock_Ret < 0) {
        *ret = unlock_Ret;
    } else {
        *ret = unlock_Ret;
    }

    return 0;
}

// The server implementation of getattr.
int watdfs_getattr(int *argTypes, void **args) {
    char *short_path = (char *)args[0];

    struct stat *statbuf = (struct stat *)args[1];

    int *ret = (int *)args[2];

    std::string full_path = get_full_path(short_path);

    int sys_ret = stat(full_path.c_str(), statbuf);

    if (sys_ret < 0) {
        *ret = -errno;
        DLOG("getattr failed for path: %s, error: -%d", full_path.c_str(), errno);
    } else {
        *ret = 0;
        DLOG("getattr succeeded for path: %s", full_path.c_str());
    }

    return 0;
}

int watdfs_mknod(int *argTypes, void **args) {
    char *short_path = (char *)args[0];
    mode_t *mode = (mode_t *)args[1];
    dev_t *dev = (dev_t *)args[2];
    int *ret = (int *)args[3];

    std::string full_path = get_full_path(short_path);

    int sys_ret = mknod(full_path.c_str(), *mode, *dev);

    if (sys_ret < 0) {
        *ret = -errno;
        DLOG("mknod failed with error '%s' for path '%s'", strerror(errno),
             full_path.c_str());
    } else {
        *ret = 0;
        DLOG("mknod succeeded for path '%s'", full_path.c_str());
    }

    return 0;
}

int watdfs_open(int *argTypes, void **args) {
    char *short_path = (char *)args[0];
    struct fuse_file_info *fi = (struct fuse_file_info *)args[1];
    int *ret = (int *)args[2];

    std::string full_path = get_full_path(short_path);

    rw_lock_lock(state_lock, RW_WRITE_LOCK);

    bool is_write = ((fi->flags & O_WRONLY) || (fi->flags & O_RDWR));

    DLOG("TRYING TO OPEN FILE: %s WITH WRITE: %d", full_path.c_str(), is_write);

    if (server_file_state.find(full_path) == server_file_state.end()) {
        struct file_state new_state;
        new_state.lock = new rw_lock_t;
        rw_lock_init(new_state.lock);
        new_state.open_for_write = is_write;
        server_file_state[full_path] = new_state;
    } else {
        auto state = server_file_state[full_path];

        DLOG("FILE IS ALREADY OPEN FOR WRITE: %s", state.open_for_write ? "TRUE" : "FALSE");

        if (is_write && state.open_for_write) {
            *ret = -EACCES;
            DLOG("File %s is already open for writing", short_path);
            rw_lock_unlock(state_lock, RW_WRITE_LOCK);
            return 0;
        } else if (is_write) {
            DLOG("FILE IS NOT OPEN FOR WRITE, ONLY FOR READ. OPENING FOR WRITE");
            state.open_for_write = true;
        } else {
            DLOG("FILE IS OPEN FOR READ. OPENING FOR READ AGAIN");
        }

        server_file_state[full_path] = state;
    }

    rw_lock_unlock(state_lock, RW_WRITE_LOCK);
    int fd = open(full_path.c_str(), fi->flags);

    if (fd < 0) {
        *ret = -errno;
        DLOG("open failed with error '%s' for path '%s'", strerror(errno),
                full_path.c_str());
    } else {
        fi->fh = fd;
        *ret = 0;
        DLOG("open succeeded for path '%s' with fd %d", full_path.c_str(), fd);
    }

    return 0;
}

int watdfs_release(int *argTypes, void **args) {
    char *short_path = (char *)args[0];
    struct fuse_file_info *fi = (struct fuse_file_info *)args[1];
    int *ret = (int *)args[2];

    std::string full_path = get_full_path(short_path);

    rw_lock_lock(state_lock, RW_WRITE_LOCK);

    auto state = server_file_state[full_path];

    if (state.open_for_write) {
        state.open_for_write = false;
    }

    server_file_state[full_path] = state;
    rw_lock_unlock(state_lock, RW_WRITE_LOCK);

    int close_ret = close(fi->fh);

    if (close_ret < 0) {
        *ret = -errno;
        DLOG("release failed with error '%s' for path '%s'", strerror(errno),
             full_path.c_str());
    } else {
        *ret = 0;
        DLOG("release succeeded for path '%s'", full_path.c_str());
    }

    return 0;
}

int watdfs_read(int *argTypes, void **args) {
    char *short_path = (char *)args[0];
    char *buf = (char *)args[1];
    size_t *size = (size_t *)args[2];
    off_t *offset = (off_t *)args[3];
    struct fuse_file_info *fi = (struct fuse_file_info *)args[4];
    int *ret = (int *)args[5];

    std::string full_path = get_full_path(short_path);

    ssize_t bytes_read = pread(fi->fh, buf, *size, *offset);

    if (bytes_read < 0) {
        *ret = -errno;
        DLOG("read failed with error '%s' for path '%s'", strerror(errno),
             full_path.c_str());
    } else {
        *ret = bytes_read;
        DLOG("read succeeded for path '%s', read %zd bytes", full_path.c_str(),
             bytes_read);
    }

    return 0;
}

int watdfs_write(int *argTypes, void **args) {
    char *buf = (char *)args[1];
    size_t *size = (size_t *)args[2];
    off_t *offset = (off_t *)args[3];
    struct fuse_file_info *fi = (struct fuse_file_info *)args[4];
    int *ret = (int *)args[5];

    std::string full_path = get_full_path((char *)args[0]);

    ssize_t written = pwrite(fi->fh, buf, *size, *offset);

    if (written < 0) {
        *ret = -errno;
        DLOG("write failed with error: %s", strerror(errno));
    } else {
        *ret = written;
        DLOG("wrote %zd bytes at offset %ld", written, *offset);
    }

    return 0;
}

int watdfs_truncate(int *argTypes, void **args) {
    char *short_path = (char *)args[0];
    off_t *newsize = (off_t *)args[1];
    int *ret = (int *)args[2];

    std::string full_path = get_full_path(short_path);
    int sys_ret = truncate(full_path.c_str(), *newsize);

    if (sys_ret < 0) {
        *ret = -errno;
        DLOG("truncate failed for '%s' with error: %s", full_path.c_str(),
             strerror(errno));
    } else {
        *ret = 0;
        DLOG("truncate succeeded for '%s' to size %ld", full_path.c_str(),
             *newsize);
    }

    return 0;
}

int watdfs_fsync(int *argTypes, void **args) {
    struct fuse_file_info *fi = (struct fuse_file_info *)args[1];
    int *ret = (int *)args[2];

    int sys_ret = fsync(fi->fh);

    if (sys_ret < 0) {
        *ret = -errno;
        DLOG("fsync failed for fh %ld: %s", fi->fh, strerror(errno));
    } else {
        *ret = 0;
        DLOG("fsync succeeded for fh %ld", fi->fh);
    }

    return 0;
}

int watdfs_utimensat(int *argTypes, void **args) {
    char *short_path = (char *)args[0];
    struct timespec *ts = (struct timespec *)args[1];
    int *ret = (int *)args[2];

    std::string full_path = get_full_path(short_path);

    int sys_ret = utimensat(AT_FDCWD, full_path.c_str(), ts, 0);

    if (sys_ret < 0) {
        *ret = -errno;
        DLOG("utimensat failed for '%s': %s", full_path.c_str(), strerror(errno));
    } else {
        *ret = 0;
        DLOG("utimensat succeeded for '%s'", full_path.c_str());
    }

    return 0;
}

// The main function of the server.
int main(int argc, char *argv[]) {
    server_persist_dir = argv[1];

    int ret = rpcServerInit();
    if (ret < 0) {
        DLOG("Server initialization failed with error '%d'", ret);
        return ret;
    }

    state_lock = new rw_lock_t;
    rw_lock_init(state_lock);

    {
        int argTypes[4];
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =
            (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);

        argTypes[3] = 0;

        ret = rpcRegister((char *)"getattr", argTypes, watdfs_getattr);
        if (ret < 0) {
            DLOG("Registration of getattr failed with error '%d'", ret);
            return ret;
        }
    }
    {
        int argTypes[5];

        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] = (1u << ARG_INPUT) | (ARG_INT << 16u);
        argTypes[2] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[3] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[4] = 0;

        ret = rpcRegister((char *)"mknod", argTypes, watdfs_mknod);
        if (ret < 0) {
            DLOG("Registration of mknod failed with error '%d'", ret);
            return ret;
        }
    }
    {
        int argTypes[4];
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] = (1u << ARG_INPUT) | (1u << ARG_OUTPUT) |
                      (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        ret = rpcRegister((char *)"open", argTypes, watdfs_open);
        if (ret < 0) {
            DLOG("Registration of open failed with error '%d'", ret);
            return ret;
        }
    }
    {
        int argTypes[4];
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        ret = rpcRegister((char *)"release", argTypes, watdfs_release);
        if (ret < 0) {
            DLOG("Registration of release failed with error '%d'", ret);
            return ret;
        }
    }
    {
        int argTypes[7];
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =
            (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[3] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[4] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[5] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[6] = 0;

        ret = rpcRegister((char *)"read", argTypes, watdfs_read);
        if (ret < 0) {
            DLOG("Registration of read failed with error '%d'", ret);
            return ret;
        }
    }
    {
        int argTypes[7];
        argTypes[0] =  (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] =  (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[3] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[4] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[5] =  (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[6]  =  0;

        ret = rpcRegister((char *)"write", argTypes, watdfs_write);
        if (ret < 0) {
            DLOG("write registration failed: %d", ret);
            return ret;
        }
    }
    {
        int argTypes[4];
        argTypes[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =  (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] =  0;

        ret = rpcRegister((char *)"truncate", argTypes, watdfs_truncate);
        if (ret < 0) {
            DLOG("truncate registration failed: %d", ret);
            return ret;
        }
    }
    {
        int argTypes[4];
        argTypes[0] =  (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =  (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] =  0;

        ret = rpcRegister((char *)"fsync", argTypes, watdfs_fsync);
        if (ret < 0) {
            DLOG("fsync registration failed: %d", ret);
            return ret;
        }
    }
    {
        int argTypes[4]; 
        argTypes[0] =  (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u; 
        argTypes[1] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] =   0;

        ret = rpcRegister((char *)"utimensat", argTypes, watdfs_utimensat);
        if (ret < 0) {
            DLOG("utimensat registration failed: %d", ret);
            return ret;
        }
    }
    {
        int argTypes[4];
        argTypes[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] = (1u << ARG_INPUT) | (ARG_INT << 16u);
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        ret = rpcRegister((char *)"lock", argTypes, watdfs_lock);
        if (ret < 0) {
            DLOG("lock registration failed: %d", ret);
            return ret;
        }
    }
    {
        int argTypes[4];
        argTypes[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] = (1u << ARG_INPUT) | (ARG_INT << 16u);
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        ret = rpcRegister((char *)"unlock", argTypes, watdfs_unlock);
        if (ret < 0) {
            DLOG("unlock registration failed: %d", ret);
            return ret;
        }
    }
    DLOG("Server initialized. Handing over control to RPC library...");
    ret = rpcExecute();

    if (ret < 0) {
        DLOG("Server execution failed with error '%d'", ret);
    }

    return ret;
}
