/*
 * Copyright 2012 Andrew Ayer
 * Copyright 2014 Cyril Cleaud
 *
 * This file is part of git-crypt.
 *
 * git-crypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * git-crypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with git-crypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify the Program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, the licensors of the Program
 * grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination
 * shall include the source code for the parts of OpenSSL used as well
 * as that of the covered work.
 */

#include "util.hpp"
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>
#if defined(__WIN32__)
#include <windows.h>
#include <stdlib.h>
#include <limits.h>
#include <io.h>
#else
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fstream>
#include <iostream>

#if defined(__WIN32__)
char *realpath(const char *path, char resolved_path[PATH_MAX]);
bool RunRedirected(const char *p_szFileName, const char *p_szParams, int *p_piExitCode, HANDLE *p_phStdOut);
#endif

int exec_command (const char* command, std::ostream& output)
{
	int		status = 0;
#if defined(__WIN32__)
    HANDLE  hPipeOut = NULL;
    char    cmdLine[4096];
    sprintf(cmdLine, "%s%s", "cmd.exe /c ", command);
    if (RunRedirected(NULL, cmdLine, &status, &hPipeOut)) {
        DWORD dwRead=0;
        char		buffer[1024];

        while (ReadFile(hPipeOut, buffer, sizeof(buffer), &dwRead, NULL) == TRUE && dwRead > 0) {
            output.write(buffer, dwRead);
        }
        CloseHandle(hPipeOut);
    } else {
        std::clog << command << ": problem creating child process (in " << __FUNCTION__ << ")." << std::endl;
		perror("RunRedirected");
		std::exit(9);
    }
#else
	ssize_t	bytes_read;
	int		pipefd[2];
	char	buffer[1024];

	if (pipe(pipefd) == -1) {
	    std::clog << "problem creating pipe (in " << __FUNCTION__ << ")." << std::endl;
		perror("pipe");
		std::exit(9);
	}

	pid_t		child = fork();
	if (child == -1) {
	    std::clog << "problem forking (in " << __FUNCTION__ << ")." << std::endl;
		close(pipefd[0]);
		close(pipefd[1]);
		perror("fork");
		std::exit(9);
	}
	if (child == 0) {
		close(pipefd[0]);
		if (pipefd[1] != 1) {
			dup2(pipefd[1], 1);
			close(pipefd[1]);
		}
		execl("/bin/sh", "sh", "-c", command, NULL);
		exit(-1);
	}
	close(pipefd[1]);

	while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
		output.write(buffer, bytes_read);
	}
	close(pipefd[0]);
	waitpid(child, &status, 0);
#endif
	return status;
}

std::string resolve_path (const char* path)
{
	char*		resolved_path_p = realpath(path, NULL);
	std::string	resolved_path(resolved_path_p);
	free(resolved_path_p);
	return resolved_path;
}

void	open_tempfile (std::fstream& file, std::ios_base::openmode mode)
{
#if defined(__WIN32__)
	const char*	tmpdir = getenv("TEMP");
#else
	const char*	tmpdir = getenv("TMPDIR");
#endif
	size_t		tmpdir_len;

	if (tmpdir) {
		tmpdir_len = strlen(tmpdir);
	} else {
		tmpdir = "/tmp";
		tmpdir_len = 4;
	}
	char*		path = new char[tmpdir_len + 18];
	strcpy(path, tmpdir);
	strcpy(path + tmpdir_len, "/git-crypt.XXXXXX");

#if defined(__WIN32__)
	char *result = _mktemp(path);
	if(result != NULL) {
		path = result;
	} else {
        std::clog << "problem with _mktemp (in " << __FUNCTION__ << ")." << std::endl;
		perror("_mktemp");
		std::exit(9);
	}
#else
	mode_t		old_umask = umask(0077);
	int		fd = mkstemp(path);
	if (fd == -1) {
	    std::clog << "problem with mkstemp (in " << __FUNCTION__ << ")." << std::endl;
		perror("mkstemp");
		std::exit(9);
	}
	umask(old_umask);
#endif

	file.open(path, mode);
	if (!file.is_open()) {
	    std::clog << path << ": problem opening file (in " << __FUNCTION__ << ")." << std::endl;
		perror("open");
		unlink(path);
		std::exit(9);
	}
	unlink(path);

#if !defined(__WIN32__)
	close(fd);
#endif
	delete[] path;
}

std::string	escape_shell_arg (const std::string& str)
{
	std::string	new_str;
	new_str.push_back('"');
	for (std::string::const_iterator it(str.begin()); it != str.end(); ++it) {
		if (*it == '"' || *it == '\\' || *it == '$' || *it == '`') {
			new_str.push_back('\\');
		}
		new_str.push_back(*it);
	}
	new_str.push_back('"');
	return new_str;
}


#if defined(__WIN32__)
char *realpath(const char *path, char resolved_path[PATH_MAX])
{
    char *return_path = 0;

    if (path) { //Else EINVAL
        if (resolved_path)
            return_path = resolved_path;
        else        //Non standard extension that glibc uses
            return_path = (char *)malloc(PATH_MAX);

        if (return_path) { //Else EINVAL
            //This is a Win32 API function similar to what realpath() is supposed to do
            size_t size = GetFullPathNameA(path, PATH_MAX, return_path, 0);

            //GetFullPathNameA() returns a size larger than buffer if buffer is too small
            if (size > PATH_MAX) {
                if (return_path != resolved_path) { //Malloc'd buffer - Unstandard extension retry
                    free(return_path);
                    return_path = (char *)malloc(size);

                    if (return_path) {
                        size_t new_size = GetFullPathNameA(path, size, return_path, 0); //Try again
                        if (new_size > size) { //If it's still too large, we have a problem, don't try again
                            free(return_path);
                            return_path = 0;
                            errno = ENAMETOOLONG;
                        } else {
                            size = new_size;
                        }
                    } else {
                        //I wasn't sure what to return here, but the standard does say to return EINVAL
                        //if resolved_path is null, and in this case we couldn't malloc large enough buffer
                        errno = EINVAL;
                    }
                } else { //resolved_path buffer isn't big enough
                    return_path = 0;
                    errno = ENAMETOOLONG;
                }
            }

            //GetFullPathNameA() returns 0 if some path resolve problem occured
            if (!size) {
                if (return_path != resolved_path) //Malloc'd buffer
                    free(return_path);

                return_path = 0;

                //Convert MS errors into standard errors
                switch (GetLastError()) {
                case ERROR_FILE_NOT_FOUND:
                    errno = ENOENT;
                    break;

                case ERROR_PATH_NOT_FOUND:
                case ERROR_INVALID_DRIVE:
                    errno = ENOTDIR;
                    break;

                case ERROR_ACCESS_DENIED:
                    errno = EACCES;
                    break;

                default: //Unknown Error
                    errno = EIO;
                    break;
                }
            }

            //If we get to here with a valid return_path, we're still doing good
            if (return_path) {
                struct stat stat_buffer;

                //Make sure path exists, stat() returns 0 on success
                if (stat(return_path, &stat_buffer)) {
                    if (return_path != resolved_path)
                        free(return_path);

                    return_path = 0;
                    //stat() will set the correct errno for us
                }
                //else we succeeded!
            }
        }
        else
            errno = EINVAL;
    }
    else
        errno = EINVAL;

    return return_path;
}

bool RunRedirected(const char *p_szFileName, const char *p_szParams, int *p_piExitCode, HANDLE *p_phStdOut)
{
    bool bResult=false;
    HANDLE hInput=NULL, hOutput=NULL;
    PROCESS_INFORMATION structProcessInfo= {0, 0, 0, 0};
    STARTUPINFO structProcessStartup;
    SECURITY_ATTRIBUTES saAttr;


    // Buffers initialization
    memset(&structProcessStartup, 0, sizeof(structProcessStartup));
    memset(&saAttr, 0, sizeof(saAttr));

    // Prepare process creation
    structProcessStartup.cb=sizeof(structProcessStartup);
    structProcessStartup.dwX=100;
    structProcessStartup.dwY=100;
    structProcessStartup.dwFlags=STARTF_USESHOWWINDOW|STARTF_USEPOSITION|STARTF_USESTDHANDLES;
    structProcessStartup.wShowWindow=SW_HIDE;

    // Default redirections
    structProcessStartup.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);

    // Set the bInheritHandle flag so pipe handles are inherited.
    saAttr.nLength=sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle=TRUE;
    saAttr.lpSecurityDescriptor=NULL;

    // Create a pipe for the child process's STDOUT.
    if(CreatePipe(&hOutput, &hInput, &saAttr, 512 * 1024) != FALSE) {
        if(p_phStdOut)
            *p_phStdOut=hOutput;
        structProcessStartup.hStdOutput=hInput;

        if(CreateProcess(NULL, (LPSTR)p_szParams, NULL, NULL, TRUE,
                         CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &structProcessStartup, &structProcessInfo) != FALSE) {
            // Wait for process to end
            WaitForSingleObject(structProcessInfo.hProcess, INFINITE);

            // Get exit code if requested by caller
            if(p_piExitCode)
                GetExitCodeProcess(structProcessInfo.hProcess, (PDWORD)p_piExitCode);

            // Close unneeded handle if needed
            CloseHandle(structProcessStartup.hStdOutput);
            CloseHandle(structProcessInfo.hProcess);
            CloseHandle(structProcessInfo.hThread);
            bResult = true;
        }
    }

    return bResult;
}
#endif
