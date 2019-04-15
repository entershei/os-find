#include<iostream>
#include <unordered_map>
#include <unordered_set>
#include <fcntl.h>
#include <cstring>
#include <zconf.h>
#include <syscall.h>
#include <dirent.h>
#include <sys/stat.h>
#include <vector>
#include <wait.h>

const std::string HELP = R"SEQ(This program search files in a directory.
Expect first arguments: <path> - path where find will be performed, or "-help".
Default behavior is print all files in directory (recursively).
Supported arguments:
    -help               - usage this program
    -inum <num>         - find file with inode = <num>
    -name <name>        - find files with name = <name>
    -size <[+=-]size>   - find files with size [more/equals/less] than <size>
    -nlinks <num>       - find files which contains <num> hardlinks
    -exec <path>        - execute file with path = <path>
)SEQ";


const size_t BUF_SIZE = 1024;

const std::unordered_set<std::string> supported_arguments = {
        "-help", "-inum", "-name", "-size", "-nlinks", "-exec"
};

void error(std::string const &message) {
    std::cerr << "Error, " << message << " " << strerror(errno) << std::endl;
}

bool is_num(std::string s, size_t pos) {
    for (size_t i = pos; i < s.size(); ++i) {
        if (s[i] < '0' || '9' < s[i]) {
            return false;
        }
    }

    return true;
}

unsigned long long ull_str(std::string s, size_t pos) {
    unsigned long long ret = 0;

    for (size_t i = pos; i < s.size(); ++i) {
        ret = ret * 10 + (s[i] - '0');
    }
    return ret;
}

std::unordered_map<std::string, std::string> parse_arg(int args, char *argv[]) noexcept(false) {
    if (args == 1) {
        throw std::invalid_argument("No arguments.");
    }

    std::unordered_map<std::string, std::string> parsed_arguments;

    for (int i = 1; i < args; ++i) {
        std::string cur_arg = argv[i];

        if (i == 1) {
            if (cur_arg == "-help") {
                parsed_arguments[cur_arg] = "";
            } else if (supported_arguments.count(cur_arg)) {
                throw std::invalid_argument("<path> or \"-help\" must be the first argument.");
            } else {
                parsed_arguments["-path"] = cur_arg;
            }
        } else {
            if (!supported_arguments.count(cur_arg)) {
                throw std::invalid_argument("Invalid argument: " + cur_arg + ".");
            } else {
                if (cur_arg == "-help") {
                    parsed_arguments[cur_arg] = "";
                } else {
                    if (i + 1 < args) {
                        std::string value = argv[i + 1];

                        if (value.empty()) {
                            throw std::invalid_argument("Expected value after" + cur_arg + ".");
                        }

                        if (cur_arg == "-size") {
                            if (value[0] != '-' && value[0] != '+' && value[0] != '=') {
                                throw std::invalid_argument("Expected value with <+/-/=size>" + cur_arg + ".");
                            }

                            if (!is_num(value, 1)) {
                                throw std::invalid_argument("Expected number after " + cur_arg + ".");
                            }
                        } else if (cur_arg == "-inum" || cur_arg == "-nlinks") {
                            if (!is_num(value, 0)) {
                                throw std::invalid_argument("Expected number after " + cur_arg + ".");
                            }
                        }

                        ++i;
                        parsed_arguments[cur_arg] = value;
                    } else {
                        throw std::invalid_argument("Expected value after" + cur_arg + ".");
                    }
                }
            }
        }
    }

    return parsed_arguments;
}

struct linux_dirent {
    unsigned long d_ino;
    off_t d_off;
    unsigned short d_reclen;
    char const d_name[];
};

void execute(std::string const &execute_path, const std::string &file_path_argument) {
    pid_t pid = fork();

    if (pid == 0) { //child
        std::string c_file_path_argument = file_path_argument + '\0';
        std::string c_executable_path = execute_path + '\0';
        std::vector<char *> args_for_execve{&(c_executable_path[0]), &(c_file_path_argument[0]), nullptr};

        int result = execve(execute_path.c_str(), args_for_execve.data(), environ);
        if (result == -1) {
            std::cerr << "Cannot execute given program" << std::endl;
        }
        exit(EXIT_FAILURE);
    } else if (pid < 0) { //bad fork
        error("can't fork");
    } else { //parent
        int wait_pid = waitpid(pid, nullptr, 0);

        if (wait_pid == -1) {
            error("problem this execution");
        }
    }
}

void check_file(std::string const &exact_filename, std::string const &path,
                const std::unordered_map<std::string, std::string> &arguments,
                struct stat const &stat_info) {

    if ((arguments.count("-inum") && ull_str(arguments.at("-inum"), 0) != stat_info.st_ino) ||
        (arguments.count("-name") && arguments.at("-name") != exact_filename) ||
        (arguments.count("-nlinks") && ull_str(arguments.at("-nlinks"), 0) != stat_info.st_nlink)) {
        return;
    } else if (arguments.count("-size")) {
        if ((arguments.at("-size")[0] == '+' && stat_info.st_size < ull_str(arguments.at("-size"), 1)) ||
            (arguments.at("-size")[0] == '-' && stat_info.st_size > ull_str(arguments.at("-size"), 1)) ||
            (arguments.at("-size")[0] == '=' && stat_info.st_size != ull_str(arguments.at("-size"), 1))) {

            return;
        }
    } else if (arguments.count("-exec")) {
        execute(arguments.at("-exec"), path);
        return;
    }

    std::cout << path << std::endl;
}


void find(std::string const &dir_name, const std::unordered_map<std::string, std::string> &arguments) {
    int fd = open(dir_name.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        error("fd fail " + dir_name);
        return;
    }

    char buf[BUF_SIZE];
    struct stat stat_info;

    while (true) {
        long nread = syscall(SYS_getdents, fd, buf, BUF_SIZE);
        if (nread == -1) {
            error("syscall \"getdents\" fail on" + dir_name);
            break;
        }
        if (nread == 0) {
            break;
        }
        for (int bpos = 0; bpos < nread;) {
            linux_dirent *dir = reinterpret_cast<linux_dirent *>(buf + bpos);
            char d_type = *(buf + bpos + dir->d_reclen - 1);
            std::string cur_file_name(dir->d_name);

            std::string cur_path = dir_name;
            if (!cur_path.empty() && cur_path[cur_path.size() - 1] != '/') {
                cur_path += '/';
            }
            cur_path += cur_file_name;

            if (d_type == DT_REG) {
                if (stat(cur_path.c_str(), &stat_info) != 0) {
                    error("can't retrieve information about file: " + cur_path);
                } else {
                    check_file(cur_file_name, cur_path, arguments, stat_info);
                }
            } else if (d_type == DT_DIR && cur_file_name != "." &&
                       cur_file_name != "..") {
                find(cur_path, arguments);
            }
            bpos += dir->d_reclen;
        }
    }

    int close_fd = close(fd);
    if (close_fd == -1) {
        error("closing fd fail");
    }
}

int main(int args, char *argv[]) {
    try {
        std::unordered_map<std::string, std::string> arguments = parse_arg(args, argv);

        if (arguments.count("-help")) {
            std::cout << HELP;
        } else {
            find(arguments.at("-path"), arguments);
        }
    } catch (const std::invalid_argument &e) {
        std::cerr << e.what() << std::endl << HELP;
    }

    return 0;
}