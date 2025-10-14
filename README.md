# 📂 MiniDrive 

**DRAFT**

*Client/Server File Synchronization System (C++)*

| Section | Content |
| :--- | :--- |
| **Objective** | Design and implement a client–server application in **C++20 or newer** that synchronizes files between a local folder and a remote server, similar to OneDrive or Dropbox. |
| **Focus** | C++, Networking, Concurrency, File Systems, Data Synchronization. |
| **Platform** | Both server and client must run on a POSIX-compliant operating system (Linux, macOS). If you use Windows, you can use WSL (Windows Subsystem for Linux) to create a compatible environment. *TODO: We may allow Windows native support in the future.* |
| **Building** | Use **CMake** as the build system. Some basic CMake configuration files will be provided to help you get started. *TODO: Make it work* |
| **Deadline** | *TODO: Set a date* |e

---

## 💻 System Overview

Your system consists of two programs:

1. **`server`**: Runs persistently, listens for client connections, and manages the file repository.
2. **`client`**: Connects to the server, optionally authenticates, and allows the user to manage and synchronize files.

---

## ⚙️ Server Requirements

| Command | `./server --port <PORT> --root <ROOT_PATH>` |
| :--- | :--- |
| **Binding** | Binds to `0.0.0.0` on the given port. |
| **Concurrency** | Accepts **multiple clients concurrently**. |
| **Public Mode (Default)** | No authentication. All unauthenticated clients share a common **"public" directory**. |
| **Authenticated Mode** | Client provides username/password. Server authenticates or registers the user and assigns a **private directory** for that user. All operations apply only inside their private directory. |
| **Root Directory** | The server's root directory (specified by *`--root <ROOT_PATH>`*) should contain all public and user directories, and all your configuration files should be here. |
| **Persistence** | User credentials and file structure must persist across server restarts. |
| **Graceful Handling** | Gracefully handle invalid commands, missing files, permission issues. |
| **Shutdown** | On termination (receiving SIGTERM), cleanly close all client connections and save any necessary state. |
| **Logging (Optional)** | Log significant events (connections, commands, errors) to stdout for debugging. |

---

## ⌨️ Client Requirements

| Command | `./client [username@]<server_ip>:<port> [--log <log_file>]` |
| :--- | :--- |
| **Connection** | Connects to the specified IP and port. |
| **Public Mode** | If no username is provided. Must print: `[warning] operating in public mode - files are visible to everyone` |
| **Authenticated Mode** | Attempts authentication if username is provided and found on server. Must ask for password from stdin. If auth is successful must print: `Logged as <username>`. |
| **Registration** | If a username is provided, but does not exist on server, must prompt: `User <username> not found. Register? (y/n):` and if the answer is `y`, then prompt (stdin) for a password and register the user. User is created on server. Application then informs about result and exits. |
| **Prompt** | Upon successful connection, displays a prompt: `>` for interactive command entry. |
| **Logging (Optional)** | If `--log <log_file>` is provided, log commands and server responses to the specified file. |

* Parameters in `<angle brackets>` are required, while those in `[square brackets]` are optional. 

---

## 🚀 Client Interactive Commands

The client must support the following commands at the `>` prompt:

| Command | Description |
| :--- | :--- |
| **`LIST [path]`** | Lists files and folders in the given path. If no path is given, lists the current directory. |
| **`UPLOAD <local_path> [remote_path]`** | Uploads a file from the client’s local file system to the server. If `remote_path` is omitted, the same name is used. |
| **`DOWNLOAD <remote_path> [local_path]`**| Downloads a file from the server to the client. If `local_path` is omitted, the same name is used. |
| **`DELETE <path>`** | Deletes a file on the server. |
| **`HELP`** | Prints a list of available commands. |
| **`EXIT`** | Closes the connection and terminates the client. |
| **`CD <path>`** | Changes the current directory to the specified path. |
| **`MKDIR <path>`** | Creates a new folder on the server. |
| **`RMDIR <path>`** | Removes a folder on the server (recursive). |
| **`MOVE <src> <dst>`** | Moves or renames a file or folder on the server. |
| **`COPY <src> <dst>`** | Copies a file or folder on the server. |
| **`SYNC <src> <dst>`** | **Synchronizes the local directory with the server (Local to Remote, one-way).** |
| | - Uploads only files that have **changed** locally (based on hash). |
| | - Deletes files on the server that were **deleted locally**. |
| | - Does **not re-upload** unchanged files. |
| | - Prints a summary of actions taken (files uploaded, deleted, skipped). |

* Parameters in `<angle brackets>` are required, while those in `[square brackets]` are optional. 
* Paths are relative to the current directory on server unless they start with `/` (absolute path). Paths on local machine behave as normal filesystem paths, no special handling needed.
* All paths are relative to user’s root directory (public or private). You must **never allow directory traversal outside this root** (e.g., `../`).
* Commands and paths are **case-sensitive**.
* `SYNC` should first get a list of files and their hashes from the server, then compare with local files to determine which files to upload or delete.
* *TODO: specify the command responses and error messages more precisely.*

---

## 📁 File handling

* Upload and download files in **binary mode** to support all file types.
* Upload and download should be done in **chunks** (e.g., 4KB) to support large files without excessive memory usage.
* How you do the chunking is up to you, but the server must be able to handle files of at least **4GB** in size.
* Support for resuming interrupted uploads/downloads is **required**, but not with the base implementation.
* Handle file I/O errors gracefully (e.g., file not found, permission denied).

### 🐌 Resuming Transfers

* Server can crash or connection can be lost at any time during file transfer.
* Client must be able to resume interrupted uploads and downloads.
* For resuming uploads, the client should first check with the server how many bytes (chunks) of the file have already been uploaded, then continue uploading from that point.
* For resuming downloads, the client should check how many bytes (chunks) of the file have already been downloaded, then continue downloading from that point.
* You can implement resuming by storing temporary files with a special extension (e.g., `.part`) and renaming them once the transfer is complete.
* Client should handle the resuming logic, so it must persist the state of interrupted transfers (e.g., in a local file). Hashes should be used to verify file integrity after download/upload is complete.

### 🤹 Multiple sessions

* In base implementation, you may allow only one user session at a time.
* By session we mean a client connected to the server with a specific username (or in public mode).
* If a second client tries to connect with the same username (or in public mode), the server should reject the connection with an appropriate error message.
* More points will be awarded if you allow multiple sessions per user. 
    * This means that multiple clients can connect simultaneously with the same username (or in public mode) and perform file operations concurrently.
    * No file should be corrupted, if two clients upload the same file at the same time, one upload may overwrite the other, but the server must not crash and other clients must not be affected.

---

## 📡 Communication Protocol

| Aspect | Requirement |
| :--- | :--- |
| **Protocol** | **JSON (recommended** via `nlohmann/json`) or a custom text-based protocol. **Must use raw TCP sockets or Asio sockets.** |
| **Client Message** | Include at least a command name and arguments. **Example (JSON):** `{"cmd": "LIST", "path": "/"}` |
| **Server Response** | Should contain `status`, `message text`. |

---

## 🔐 Authentication and Passwords

| Aspect | Requirement |
| :--- | :--- |
| **Authentication** | Optional; default is **public mode**. |
| **Credentials** | When provided, the server must **authenticate or register** the user. |
| **Security** | Passwords must **never** be stored as **plain text**. |
| **Hashing** | Use hashing (e.g., SHA-256, bcrypt) with a crypto library. Must use **salt**. |
| **Storage** | Store user credentials and metadata in a simple **file-based database**. |

---

## 🛠️ Allowed and Technical Requirements

### Allowed Libraries

| Category | Recommended Libraries |
| :--- | :--- |
| **Networking** | **Asio** (standalone version allowed) |
| **Serialization** | **nlohmann/json** |
| **Crypto** | **OpenSSL / libsodium / Crypto++** *TODO: Pick one* |
| **Logging (Optional)** | **spdlog** |
| **Build System** | **CMake** |
| **Restriction** | Do **not** use any other libraries besides those listed above and the C++ standard library. |

### Technical Requirements

| Requirement | Details |
| :--- | :--- |
| **Language** | C++20 or later |
| **Networking** | TCP (Asio or BSD sockets) |
| **Threads/Concurrency** | `std::thread`, `std::mutex`, or **Asio async model** |
| **Filesystem** | `std::filesystem` for file handling |
| **Error Handling** | Gracefully handle failed transfers, invalid commands, missing files. |
| **Security** | **Never allow directory traversal outside user’s root folder.** |

---

## ✅ Grading Breakdown (Total: 30 points)

| Criteria | Description | Points |
| :--- | :--- | :--- |
| **Core File Commands** | Working with one directory LIST, UPLOAD, DOWNLOAD, DELETE, server handles at least one client simultaneously | 5 |
| **Folder Commands** | Working with directories CD, MKDIR, RMDIR, MOVE, COPY | 5 |
| **Synchronization** | SYNC uploads changes, handles deletions (Local to Remote) | 4 |
| **Authentication** | Public/private directories, hashed passwords (salted) | 5 |
| **Server Concurrency** | Handles multiple clients simultaneously | 5 |
| **Resume Transfers** | Supports resuming interrupted uploads/downloads | 3 |
| **Robustness** | Graceful error handling, no crashes on invalid input | 3 |
| **Subtotal** | | **30** |
| **Logging** | Optional, but appreciated for clarity and debugging | 1 |
| **Multiple Sessions** | Optional, but appreciated for extra challenge | 2 |
| **TOTAL** | | **33** |