//
// Starter code for CS 454/654
// You SHOULD change this file
//

#include "watdfs_client.h"

#include "debug.h"
INIT_LOG

#include <algorithm>  // for std::min
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include "rw_lock.h"
#include "rpc.h"

struct WatDFSCacheEntry {
    time_t Tc;      // Last validation time
    int open_flag;  // O_RDONLY, O_WRONLY, etc.
    int local_fh;
    int server_fh;
    bool is_write;
    bool is_open;
};

struct WatDFSClientState {
    std::unordered_set<std::string> release_in_progress;
    std::string cache_dir;  // Path to local cache directory
    time_t cache_interval;  // Freshness interval (seconds)
    std::unordered_map<std::string, WatDFSCacheEntry>
        cache_map;  // remote cache file path to watdfscache entry
};

std::string get_full_path(struct WatDFSClientState *userdata,
                          const char *short_path) {
    std::string full_path = userdata->cache_dir + short_path;
    DLOG("Full path: %s\n", full_path.c_str());
    return full_path;
}

int rpc_call_utimensat(void *userdata, const char *path,
                  const struct timespec ts[2]) {
    int ARG_COUNT = 3;
    void **args = new void *[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;
    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)pathlen;
    args[0] = (void *)path;

    size_t ts_size = 2 * sizeof(struct timespec);
    arg_types[1] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)ts_size;
    args[1] = (void *)ts;

    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    int retcode = 0;
    args[2] = &retcode;

    arg_types[3] = 0;

    int rpc_ret = rpcCall((char *)"utimensat", arg_types, args);
    int fxn_ret = 0;

    if (rpc_ret < 0) {
        DLOG("utimensat rpc failed for '%s' with error %d", path, rpc_ret);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    delete[] args;
    return fxn_ret;
}

int rpc_call_lock(void *userdata, const char *path, rw_lock_mode_t mode) {
    int ARG_COUNT = 3;
    void **args = new void *[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];
    
    int pathlen = strlen(path) + 1;
    int ret = 0;

    arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;
    args[0] = (void*) path;
    arg_types[1] = (1 << ARG_INPUT) | (ARG_INT << 16);
    args[1] = (void*) &mode;
    arg_types[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16);
    args[2] = (void*) &ret;
    arg_types[3] = 0;


    ret = rpcCall((char*)"lock", arg_types, args);

    int func_ret = 0;
    if(ret < 0) {
        func_ret = -EINVAL;
    } else {
        func_ret = ret;
    }

    delete[] args;
    return func_ret;
}

int rpc_call_unlock(void *userdata, const char *path, rw_lock_mode_t mode) {
    int ARG_COUNT = 3;

    void **args = new void*[ARG_COUNT];

    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;
    int ret = 0;

    arg_types[0] = (1 << ARG_INPUT) | (1 << ARG_ARRAY) | (ARG_CHAR << 16) | pathlen;
    args[0] = (void*) path;
    arg_types[1] = (1 << ARG_INPUT) | (ARG_INT << 16);
    args[1] = (void*) &mode;
    arg_types[2] = (1 << ARG_OUTPUT) | (ARG_INT << 16);
    args[2] = (void*) &ret;
    arg_types[3] = 0;
    ret = rpcCall((char*)"unlock", arg_types, args);

    int func_ret = 0;
    if(ret < 0) {
        func_ret = -EINVAL;
    } else {
        func_ret = ret;
    }

    delete[] args;
    return func_ret;
}

int rpc_call_truncate(void *userdata, const char *path, off_t newsize) {
    int ARG_COUNT = 3;
    void **args = new void *[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;
    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)pathlen;
    args[0] = (void *)path;

    arg_types[1] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
    args[1] = &newsize;

    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    int retcode = 0;
    args[2] = &retcode;

    arg_types[3] = 0;

    int rpc_ret = rpcCall((char *)"truncate", arg_types, args);
    int fxn_ret = 0;

    if (rpc_ret < 0) {
        DLOG("truncate rpc failed for '%s' with error %d", path, rpc_ret);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    delete[] args;
    return fxn_ret;
}

int rpc_call_getattr(void *userdata, const char *path, struct stat *statbuf) {
    DLOG("rpc_call_getattr called for '%s'", path);

    int ARG_COUNT = 3;
    void **args = new void *[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;

    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)pathlen;

    args[0] = (void *)path;

    arg_types[1] = (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)sizeof(struct stat);  // statbuf
    args[1] = (void *)statbuf;

    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);

    int retcode = 0;
    args[2] = &retcode;

    arg_types[3] = 0;

    int rpc_ret = rpcCall((char *)"getattr", arg_types, args);

    DLOG("rpc_call_getattr returned %d", rpc_ret);

    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("getattr rpc failed with error '%d'", rpc_ret);

        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    if (fxn_ret < 0) {
        memset(statbuf, 0, sizeof(struct stat));
    }

    delete[] args;
    return fxn_ret;
}

int rpc_call_open(void *userdata, const char *path, struct fuse_file_info *fi) {
    int ARG_COUNT = 3;
    void **args = new void *[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;
    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)pathlen;
    args[0] = (void *)path;

    arg_types[1] = (1u << ARG_INPUT) | (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) |
                   (ARG_CHAR << 16u) | (uint)sizeof(struct fuse_file_info);
    args[1] = (void *)fi;

    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    int retcode = 0;
    args[2] = &retcode;

    arg_types[3] = 0;

    int rpc_ret = rpcCall((char *)"open", arg_types, args);

    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("open rpc failed with error '%d' for path '%s'", rpc_ret, path);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }
    delete[] args;
    return fxn_ret;
}


// Renamed original function
int rpc_call_release(void *userdata, const char *path, struct fuse_file_info *fi) {
    int ARG_COUNT = 3;
    void **args = new void *[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;
    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)pathlen;
    args[0] = (void *)path;

    arg_types[1] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)sizeof(struct fuse_file_info);
    args[1] = (void *)fi;

    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    int retcode = 0;
    args[2] = &retcode;

    arg_types[3] = 0;

    int rpc_ret = rpcCall((char *)"release", arg_types, args);

    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("release rpc failed with error '%d' for path '%s'", rpc_ret, path);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    delete[] args;
    return fxn_ret;
}

int rpc_call_write(void *userdata, const char *path, const char *buf, size_t size,
              off_t offset, struct fuse_file_info *fi) {
    ssize_t total_written = 0;
    size_t bytes_remaining = size;
    const char *current_buf = buf;

    while (bytes_remaining > 0) {
        size_t chunk_size = std::min<size_t>(bytes_remaining, MAX_ARRAY_LEN);
        int ARG_COUNT = 6;
        void **args = new void *[ARG_COUNT];
        int arg_types[ARG_COUNT + 1];

        int pathlen = strlen(path) + 1;
        arg_types[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | pathlen;
        args[0] = (void *)path;

        arg_types[1] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) |
                       (ARG_CHAR << 16u) | chunk_size;
        args[1] = (void *)current_buf;

        arg_types[2] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        args[2] = &chunk_size;

        arg_types[3] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        args[3] = &offset;

        arg_types[4] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) |
                       (ARG_CHAR << 16u) | sizeof(*fi);
        args[4] = (void *)fi;

        arg_types[5] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        int retcode = 0;
        args[5] = &retcode;

        arg_types[6] = 0;

        int rpc_ret = rpcCall((char *)"write", arg_types, args);
        delete[] args;

        if (rpc_ret < 0 || retcode < 0) {
            return rpc_ret < 0 ? rpc_ret : retcode;
        }

        ssize_t written = retcode;
        if (written <= 0) break;

        total_written += written;
        bytes_remaining -= written;
        current_buf += written;
        offset += written;
    }

    return total_written > 0 ? total_written : -EIO;
}


bool is_file_open(void *userdata, const char *path) {
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);
    auto it = state->cache_map.find(full_path);
    return it != state->cache_map.end() && it->second.is_open;
}

// READ AND WRITE DATA
int rpc_call_read(void *userdata, const char *path, char *buf, size_t size,
             off_t offset, struct fuse_file_info *fi) {
    ssize_t total_bytes_read = 0;
    size_t bytes_remaining = size;
    off_t current_offset = offset;

    while (bytes_remaining > 0) {
        size_t bytes_to_read = std::min<size_t>(bytes_remaining, MAX_ARRAY_LEN);

        int ARG_COUNT = 6;
        void **args = new void *[ARG_COUNT];
        int arg_types[ARG_COUNT + 1];

        int pathlen = strlen(path) + 1;
        arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) |
                       (ARG_CHAR << 16u) | (uint)pathlen;
        args[0] = (void *)path;

        arg_types[1] = (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) |
                       (ARG_CHAR << 16u) | (uint)bytes_to_read;
        args[1] = (void *)(buf + total_bytes_read);

        arg_types[2] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        args[2] = &bytes_to_read;

        arg_types[3] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        args[3] = &current_offset;

        arg_types[4] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) |
                       (ARG_CHAR << 16u) | (uint)sizeof(struct fuse_file_info);
        args[4] = (void *)fi;

        arg_types[5] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        int retcode = 0;
        args[5] = &retcode;

        arg_types[6] = 0;

        int rpc_ret = rpcCall((char *)"read", arg_types, args);

        if (rpc_ret < 0) {
            delete[] args;
            return -EINVAL;
        }

        if (retcode < 0) {
            delete[] args;
            return retcode;
        }

        int bytes_read = retcode;
        if (bytes_read == 0) {
            delete[] args;
            return total_bytes_read;
        }

        total_bytes_read += bytes_read;
        bytes_remaining -= bytes_read;
        current_offset += bytes_read;

        delete[] args;

        if ((size_t)bytes_read < bytes_to_read) {
            break;
        }
    }

    return total_bytes_read;
}


int download_file_content(void *userdata, const char *path) {
    DLOG("=========== download_file_content ===========");
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);
    struct stat *server_stat = new struct stat;
    int local_fd = -1;
    struct fuse_file_info *fi = new struct fuse_file_info;
    
    // Save original flags and set temporary flags for download
    fi->flags = O_RDONLY;

    // Get file attributes from server
    int getattr_ret = rpc_call_getattr(userdata, path, server_stat);
    if (getattr_ret < 0) {
        DLOG("File %s does not exist on the server", path);
        delete server_stat;
        return getattr_ret;
    }
    
    // Open file on server for reading
    int opened = rpc_call_open(userdata, path, fi);
    if (opened < 0) {
        DLOG("Failed to open file on server: %s with error %d", path, opened);
        delete server_stat;
        return opened;
    }
    
    // Open file locally for writing
    local_fd = open(full_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (local_fd < 0) {
        DLOG("Failed to open file on client: %s with error %d", path, local_fd);
        rpc_call_release(userdata, path, fi);
        delete server_stat;
        return local_fd;
    }
    
    // Lock the file
    int lock_ret = rpc_call_lock(userdata, path, RW_READ_LOCK);
    if (lock_ret < 0) {
        DLOG("Failed to lock file: %s with error %d", path, lock_ret);
        close(local_fd);
        rpc_call_release(userdata, path, fi);
        delete server_stat;
        return lock_ret;
    }
    
    // Read file contents from server and write to local file
    char buf[MAX_ARRAY_LEN];
    off_t off = 0;
    int bytes_read = rpc_call_read(userdata, path, buf, MAX_ARRAY_LEN, off, fi);
    if (bytes_read < 0) {
        DLOG("Failed to read remote file: %s with error %d", path, bytes_read);
        close(local_fd);
        rpc_call_release(userdata, path, fi);
        delete server_stat;
        return bytes_read;
    }

    // Unlock the file
    int unlock_ret = rpc_call_unlock(userdata, path, RW_READ_LOCK);
    if (unlock_ret < 0) {
        DLOG("Failed to unlock file: %s with error %d", path, unlock_ret);
        close(local_fd);
        rpc_call_release(userdata, path, fi);
        delete server_stat;
        return unlock_ret;
    }
    
    int bytes_written = write(local_fd, buf, bytes_read);
    if (bytes_written < 0) {
        DLOG("Failed to write to local file: %s with error %d", path, bytes_written);
        close(local_fd);
        rpc_call_release(userdata, path, fi);
        delete server_stat;
        return bytes_written;
    }
    
    // Clean up
    close(local_fd);
    rpc_call_release(userdata, path, fi);
    delete server_stat;
    
    return 0;
}

int upload_file_content(void *userdata, const char *path) {
    DLOG("=========== upload_file_content ===========");
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);
    
    // Cannot upload if file is not open in write mode
    if (!is_file_open(userdata, path)) {
        DLOG("File not open: %s", path);
        return -EBADF;
    }
    
    auto entry = state->cache_map[full_path];
    if (!entry.is_write) {
        DLOG("File not open for writing: %s", path);
        return -EACCES;
    }
    
    // Create temporary file info for server communication
    struct fuse_file_info temp_fi;
    temp_fi.flags = O_RDWR;
    temp_fi.fh = entry.server_fh;
    
    // Read from local file and write to server
    char buf[MAX_ARRAY_LEN];
    int bytes_read;
    off_t off = 0;
    
    // Lock the file
    int lock_ret = rpc_call_lock(userdata, path, RW_WRITE_LOCK);
    if (lock_ret < 0) {
        DLOG("Failed to lock file: %s with error %d", path, lock_ret);
        return lock_ret;
    }

    close(entry.local_fh);  
    int old_flags = entry.open_flag;
    

    int local_fh = open(full_path.c_str(), O_RDWR);
    while ((bytes_read = read(local_fh, buf, MAX_ARRAY_LEN)) > 0) {
        int bytes_written = rpc_call_write(userdata, path, buf, bytes_read, off, &temp_fi);
        if (bytes_written < 0) {
            DLOG("Could not write to remote file: %s with error %d", path, bytes_written);
            return bytes_written;
        }
        
        DLOG("Wrote %d bytes to remote file: %s", bytes_written, path);
        off += bytes_written;
    }

    close(local_fh);    
    int local_fc = open(full_path.c_str(), old_flags, 0644);
    if (local_fc < 0) {
        DLOG("Failed to open file on client: %s with error %d", path, local_fc);
        return local_fc;
    }

    state->cache_map[full_path].local_fh = local_fc;
    
    // Unlock the file
    int unlock_ret = rpc_call_unlock(userdata, path, RW_WRITE_LOCK);
    if (unlock_ret < 0) {
        DLOG("Failed to unlock file: %s with error %d", path, unlock_ret);
        return unlock_ret;
    }
    
    // Update timestamp
    state->cache_map[full_path].Tc = time(0);
    
    return 0;
}

int watdfs_cli_open(void *userdata, const char *path, struct fuse_file_info *fi) {
    DLOG("=========== watdfs_cli_open ===========");
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);
    int access_mode = fi->flags & O_ACCMODE;
    bool write_mode = (access_mode == O_WRONLY || access_mode == O_RDWR);

    DLOG("OPENING FILE: %s WITH WRITE: %s", path, write_mode ? "true" : "false");
    
    // Check if file is already open
    if (is_file_open(userdata, path)) {
        DLOG("File already open: %s", path);
        return -EMFILE;
    }

    if (state->release_in_progress.find(full_path) != state->release_in_progress.end()) {
        DLOG("File is being released: %s", path);
        return -EMFILE;
    }
    
    // Step 1: Download file content to local cache
    int download_result = download_file_content(userdata, path);
    if (download_result < 0) {
        DLOG("Failed to download file: %s with error %d", path, download_result);
        return download_result;
    }
    
    // Step 2: Open file on server with original flags
    int opened = rpc_call_open(userdata, path, fi);
    if (opened < 0) {
        DLOG("Failed to open file on server: %s with error %d", path, opened);
        return opened;
    }
    
    // Step 3: Open file locally with original flags
    int local_fd = open(full_path.c_str(), fi->flags, 0644);
    if (local_fd < 0) {
        rpc_call_release(userdata, path, fi);
        DLOG("Failed to open file locally: %s with error %d", path, local_fd);
        return local_fd;
    }
    
    // Step 4: Create cache entry with metadata
    auto entry = WatDFSCacheEntry{
        time(0),            // Tc - current time
        fi->flags,          // Original flags
        local_fd,           // Local file descriptor
        (int)fi->fh,        // Server file handle
        write_mode,         // Is write mode
        true                // Is open
    };
    
    state->cache_map[full_path] = entry;
    
    return 0;
}

int watdfs_cli_release(void *userdata, const char *path, struct fuse_file_info *fi) {
    DLOG("=========== watdfs_cli_release ===========");
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);
    
    // Check if file is open
    if (!is_file_open(userdata, path)) {
        DLOG("File not open: %s", path);
        return -EBADF;
    }

    state->release_in_progress.insert(full_path);
    
    WatDFSCacheEntry entry = state->cache_map[full_path];
    
    // Step 1: If file was opened in write mode, flush to server
    if (entry.is_write) {
        DLOG("File was open for writing, uploading to server: %s", path);
        int upload_result = upload_file_content(userdata, path);
        if (upload_result < 0) {
            DLOG("Failed to upload file: %s with error %d", path, upload_result);
            state->release_in_progress.erase(full_path);
            return upload_result;
        }
    }
    
    // Step 2: Update file metadata (timestamps)
    auto st = new struct stat;
    int getattr_ret = stat(full_path.c_str(), st);
    if (getattr_ret >= 0) {
        auto ts = new struct timespec[2];
        ts[0] = st->st_mtim;
        ts[1] = st->st_mtim;
        
        int utimensat_ret = rpc_call_utimensat(userdata, path, ts);
        if (utimensat_ret < 0) {
            DLOG("Warning: Failed to set timestamps: %s with error %d", path, utimensat_ret);
            // Continue anyway - this is not fatal
        }
        
        delete[] ts;
    }
    delete st;
    
    // Step 3: Close file on server
    int released = rpc_call_release(userdata, path, fi);
    if (released < 0) {
        DLOG("Failed to release file on server: %s with error %d", path, released);
        state->release_in_progress.erase(full_path);
        return released;
    }
    
    // Step 4: Close file locally
    int closed = close(entry.local_fh);
    if (closed < 0) {
        DLOG("Failed to close file locally: %s with error %d", path, closed);
        state->release_in_progress.erase(full_path);
        return closed;
    }
    
    // Step 5: Update cache metadata
    state->cache_map[full_path].is_open = false;
    state->cache_map[full_path].is_write = false;
    state->release_in_progress.erase(full_path);
    return 0;
}

int watdfs_cli_truncate(void *userdata, const char *path, off_t newsize) {
    DLOG("=========== watdfs_cli_truncate ===========");
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);
    
    // Check if file is open in read-only mode
    auto it = state->cache_map.find(full_path);
    if (it != state->cache_map.end() && it->second.is_open && !it->second.is_write) {
        DLOG("Cannot truncate a file opened in read-only mode: %s", path);
        return -EMFILE;
    }
    
    // Truncate local file
    int local_ret = truncate(full_path.c_str(), newsize);
    if (local_ret < 0) {
        DLOG("Failed to truncate local file: %s with error %d", path, local_ret);
        return local_ret;
    }
    
    // Truncate server file
    int server_ret = rpc_call_truncate(userdata, path, newsize);
    if (server_ret < 0) {
        DLOG("Failed to truncate server file: %s with error %d", path, server_ret);
        return server_ret;
    }
    
    // Update timestamp
    if (it != state->cache_map.end()) {
        state->cache_map[full_path].Tc = time(0);
    }
    
    return 0;
}

bool freshness_check(WatDFSClientState *state, const char *path) {
    if (state->cache_map.find(path) == state->cache_map.end()) {
        return false;
    }

    auto entry = state->cache_map[path];
    time_t now = time(0);
    if (now - entry.Tc < state->cache_interval) {
        state->cache_map[path].Tc = now;
        return true;
    }

    struct stat *st = new struct stat;
    int getattr_ret = rpc_call_getattr((void*)state, path, st);
    if (getattr_ret < 0) {
        return false;
    }

    time_t Ts = st->st_mtime;
    if (Ts == entry.Tc) {
        state->cache_map[path].Tc = now;
        return true;
    }
    
    return false;
}

void *watdfs_cli_init(struct fuse_conn_info *conn, const char *path_to_cache,
                      time_t cache_interval, int *ret_code) {
    int rpc_ret = rpcClientInit();

    if (rpc_ret < 0) {
        *ret_code = -EINVAL;
        return nullptr;
    }

    auto *state = new WatDFSClientState();

    state->cache_dir = path_to_cache;
    state->cache_interval = cache_interval;

    *ret_code = 0;
    return (void *)state;
}

void watdfs_cli_destroy(void *userdata) {
    int ret = rpcClientDestroy();
    if (ret < 0) {
        DLOG("RPC client destroy failed with error '%d'", ret);
    }

    delete userdata;
}

// Renamed original function

// New empty function with original name
int watdfs_cli_getattr(void *userdata, const char *path, struct stat *statbuf) {
    DLOG("=========== watdfs_cli_getattr ===========");
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);

    // FILE IS NOT OPEN
    if (!is_file_open(userdata, path)) {
        // 1. download file to client
        int downloaded = download_file_content(userdata, path);
        if (downloaded < 0) {
            DLOG("Failed to download file: %s with error %d", path, downloaded);
            return downloaded;
        }
        // 2. get attributes of local file
        int getattr_ret = stat(full_path.c_str(), statbuf);
        if (getattr_ret < 0) {
            DLOG("Failed to get attributes for file: %s with error %d", path, getattr_ret);
            return getattr_ret;
        }
        // 3. update last validation
        if (state->cache_map.find(full_path) == state->cache_map.end()) {
            state->cache_map[full_path] = WatDFSCacheEntry{
                time(0),
                O_RDWR,
                -1,
                -1,
                false,
                false
            };
        } else {
            state->cache_map[full_path].Tc = time(0);
        }
    } else {
        // FILE IS OPEN
        auto entry = state->cache_map[full_path];
        // 1. check file freshness
        bool is_fresh = freshness_check(state, path);
        // 2. get file open mode
        int is_write = entry.is_write;
        int server_fh = entry.server_fh;

        // 3. if file is open for read, download file again if not fresh, perform operation, and update last validation
        if(!is_write) {
            if (!is_fresh) {
                int downloaded = download_file_content(userdata, path);
                if (downloaded < 0) {
                    DLOG("Failed to download file: %s with error %d", path, downloaded);
                    return downloaded;
                }
            }

            int getattr_ret = stat(full_path.c_str(), statbuf);
            if (getattr_ret < 0) {
                DLOG("Failed to get attributes for file: %s with error %d", path, getattr_ret);
                return getattr_ret;
            }

            state->cache_map[full_path].Tc = time(0); 
        } else {
            // 4. if file is open for write, we can stat the file locally
            int getattr_ret = stat(full_path.c_str(), statbuf);
            if (getattr_ret < 0) {
                DLOG("Failed to get attributes for file: %s with error %d", path, getattr_ret);
                return getattr_ret;
            }

            state->cache_map[full_path].Tc = time(0);
        }

    }

    return 0;
}

// CREATE, OPEN AND CLOSE
int watdfs_cli_mknod(void *userdata, const char *path, mode_t mode, dev_t dev) {
    DLOG("=========== watdfs_cli_mknod ===========");
    int ARG_COUNT = 4;
    void **args = new void *[ARG_COUNT];

    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;

    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)pathlen;
    args[0] = (void *)path;

    arg_types[1] = (1u << ARG_INPUT) | (ARG_INT << 16u);
    args[1] = &mode;

    arg_types[2] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
    args[2] = &dev;

    arg_types[3] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    int retcode = 0;
    args[3] = &retcode;

    arg_types[4] = 0;

    int rpc_ret = rpcCall((char *)"mknod", arg_types, args);

    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("mknod rpc failed with error '%d'", rpc_ret);

        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    delete[] args;
    return fxn_ret;
}


int watdfs_cli_read(void *userdata, const char *path, char *buf, size_t size,
                    off_t offset, struct fuse_file_info *fi) {
    DLOG("=========== watdfs_cli_read ===========");
    // TODO: Implement new read functionality
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);
    if (!is_file_open(userdata, path)) {
        return -EBADR;
    }

    struct fuse_file_info temp_fi;


    auto entry = state->cache_map[full_path];
    int old_flags = entry.open_flag;
    bool old_is_write = entry.is_write;
    memcpy(&temp_fi, fi, sizeof(struct fuse_file_info));
    temp_fi.flags = old_flags;
    temp_fi.fh = entry.server_fh;
    

    bool fresh = freshness_check(state, path);
    if (!fresh && !old_is_write) {
        // RELEASE FILE
        int release_ret = rpc_call_release(userdata, path, &temp_fi);
        if (release_ret < 0) {
            DLOG("Failed to release file: %s with error %d", path, release_ret);
            return release_ret;
        }

        close(entry.local_fh);

        int downloaded = download_file_content(userdata, path);
        if (downloaded < 0) {
            DLOG("Failed to download file: %s with error %d", path, downloaded);
            return downloaded;
        }

        int open_ret = open(full_path.c_str(), old_flags, 0644);
        if (open_ret < 0) {
            DLOG("Failed to open file on client: %s with error %d", path, open_ret);
            return open_ret;
        }

        int rpc_open_ret = rpc_call_open(userdata, path, fi);
        if (rpc_open_ret < 0) {
            DLOG("Failed to open file on server: %s with error %d", path, rpc_open_ret);
            return rpc_open_ret;
        }

        auto new_entry = WatDFSCacheEntry{
            time(0),
            old_flags,
            open_ret,
            (int)fi->fh,
            old_is_write,
            true
        };

        state->cache_map[full_path] = new_entry;        
    }

    entry = state->cache_map[full_path];
    int local_fh = entry.local_fh;
    int bytes_read = pread(local_fh, buf, size, offset);
    if (bytes_read < 0) {
        DLOG("Failed to read file: %s with error %d", path, bytes_read);
        return bytes_read;
    }

    return bytes_read;
}

int watdfs_cli_write(void *userdata, const char *path, const char *buf,
                     size_t size, off_t offset, struct fuse_file_info *fi) {
    DLOG("=========== watdfs_cli_write ===========");
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);
    if (!is_file_open(userdata, path)) {
        return -EBADR;
    }

    auto entry = state->cache_map[full_path];
    bool is_write = entry.is_write;

    if (!is_write) {
        return -EPERM;
    }

    int bytes_written = pwrite(entry.local_fh, buf, size, offset);
    if (bytes_written < 0) {
        DLOG("Failed to write file: %s with error %d", path, bytes_written);
        return bytes_written;
    }

    bool fresh = freshness_check(state, path);
    if (!fresh) {
        int upload_ret = upload_file_content(userdata, path);
        if (upload_ret < 0) {
            DLOG("Failed to upload file: %s with error %d", path, upload_ret);
            return upload_ret;
        }

        state->cache_map[full_path].Tc = time(0);
    }

    return bytes_written;
}


int rpc_call_fsync(void *userdata, const char *path,
                     struct fuse_file_info *fi) {
    DLOG("=========== rpc_call_fsync ===========");
    int ARG_COUNT = 3;
    void **args = new void *[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;
    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)pathlen;
    args[0] = (void *)path;

    arg_types[1] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint)sizeof(*fi);
    args[1] = (void *)fi;

    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    int retcode = 0;
    args[2] = &retcode;

    arg_types[3] = 0;

    int rpc_ret = rpcCall((char *)"fsync", arg_types, args);
    int fxn_ret = 0;

    if (rpc_ret < 0) {
        DLOG("fsync rpc failed for '%s' with error %d", path, rpc_ret);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    delete[] args;
    return fxn_ret;
}

int watdfs_cli_fsync(void *userdata, const char *path,
                     struct fuse_file_info *fi) {
    DLOG("=========== watdfs_cli_fsync ===========");
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);

    if(!is_file_open(userdata, path)) {
        return -EMFILE;
    }

    auto entry = state->cache_map[full_path];
    if(!entry.is_write) {
        return -EPERM;
    }

    int upload_ret = upload_file_content(userdata, path); 
    if (upload_ret < 0) {
        DLOG("fsync - Could not upload file %s, with error code %d", full_path, upload_ret);
        return upload_ret;
    }

    state->cache_map[full_path].Tc = time(0);

    return 0;
}

int watdfs_cli_utimensat(void *userdata, const char *path,
                         const struct timespec ts[2]) {
    DLOG("=========== watdfs_cli_utimensat ===========");
    auto *state = (WatDFSClientState *)userdata;
    std::string full_path = get_full_path(state, path);
    struct fuse_file_info *fi = new struct fuse_file_info;
    fi->flags = O_RDWR;

    if (!is_file_open(userdata, path)) {
        int downloaded = download_file_content(userdata, path);
        if (downloaded < 0) {
            DLOG("Failed to download file: %s with error %d", path, downloaded);
            return downloaded;
        }

        int open_ret = open(full_path.c_str(), O_RDONLY, 0644);
        if (open_ret < 0) {
            DLOG("Failed to open file on client: %s with error %d", path, open_ret);
            return open_ret;
        }

        int rpc_open_ret = rpc_call_open(userdata, path, fi);
        if (rpc_open_ret < 0) {
            DLOG("Failed to open file on server: %s with error %d", path, rpc_open_ret);
            return rpc_open_ret;
        }
        // 2. get attributes of local file
        int utimensat_ret = utimensat(AT_FDCWD, full_path.c_str(), ts, 0);
        if (utimensat_ret < 0) {
            DLOG("Failed to set timestamps for file: %s with error %d", path, utimensat_ret);
            return utimensat_ret;
        }

        int upload_ret = upload_file_content(userdata, path);
        if (upload_ret < 0) {
            DLOG("Failed to upload file: %s with error %d", path, upload_ret);
            return upload_ret;
        }

        int rpc_release_ret = rpc_call_release(userdata, path, fi);
        if (rpc_release_ret < 0) {
            DLOG("Failed to release file: %s with error %d", path, rpc_release_ret);
            return rpc_release_ret;
        }

        int close_ret = close(open_ret);
        if (close_ret < 0) {
            DLOG("Failed to close file on client: %s with error %d", path, close_ret);
            return close_ret;
        }
    } else {
        // File is open
        auto entry = state->cache_map[full_path];
        // 1. check file freshness
        bool is_fresh = freshness_check(state, path);
        // 2. get file open mode
        int is_write = entry.is_write;

        int utimensat_ret = utimensat(AT_FDCWD, full_path.c_str(), ts, 0);
        if (utimensat_ret < 0) {
            DLOG("Failed to set timestamps for file: %s with error %d", path, utimensat_ret);
            return utimensat_ret;
        }

        int server_fh = entry.server_fh;

        if (!is_write) {
            return -EMFILE;
        }

        if(!is_fresh) {
            int upload_ret = upload_file_content(userdata, path);
            if (upload_ret < 0) {
                DLOG("Failed to upload file: %s with error %d", path, upload_ret);
                return upload_ret;
            }
            state->cache_map[full_path].Tc = time(0);
            return upload_ret;
        }
    }

    // TODO: Implement
    return 0;
}

