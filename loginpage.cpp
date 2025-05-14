#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <functional>
#include <cctype>
#include <limits>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

using namespace std;

class UserAuthenticator {
    struct User {
        string username;
        string email;
        string passwordHash;
        string securityQuestion;
        string securityAnswerHash;
    };

    vector<User> users;
    const string fileName = "users.dat";
    const string salt = "SECURE_SALT_1234"; // Should be securely stored in production

    void clearScreen() {
        #ifdef _WIN32
            system("cls");
        #else
            system("clear");
        #endif
    }

    string hashPassword(const string& password) {
        return to_string(hash<string>{}(password + salt));
    }

    void loadUsers() {
        users.clear();
        ifstream file(fileName);
        if (!file) return;

        string line;
        while (getline(file, line)) {
            size_t pos[4];
            int idx = 0;
            size_t start = 0;
            while ((pos[idx] = line.find('|', start)) != string::npos && idx < 4) {
                start = pos[idx++] + 1;
            }
            if (idx == 4) {
                User user;
                user.username = line.substr(0, pos[0]);
                user.email = line.substr(pos[0]+1, pos[1]-pos[0]-1);
                user.passwordHash = line.substr(pos[1]+1, pos[2]-pos[1]-1);
                user.securityQuestion = line.substr(pos[2]+1, pos[3]-pos[2]-1);
                user.securityAnswerHash = line.substr(pos[3]+1);
                users.push_back(user);
            }
        }
    }

    void saveUsers() {
        ofstream file(fileName);
        for (const User& user : users) {
            file << user.username << "|"
                 << user.email << "|"
                 << user.passwordHash << "|"
                 << user.securityQuestion << "|"
                 << user.securityAnswerHash << "\n";
        }
    }

    bool isValidEmail(const string& email) {
        size_t at = email.find('@');
        size_t dot = email.find_last_of('.');
        return (at != string::npos) && (dot != string::npos) && (at < dot);
    }

    bool isStrongPassword(const string& password) {
        if (password.length() < 8) return false;
        bool hasUpper = false, hasLower = false, hasDigit = false;
        for (char c : password) {
            if (isupper(c)) hasUpper = true;
            if (islower(c)) hasLower = true;
            if (isdigit(c)) hasDigit = true;
        }
        return hasUpper && hasLower && hasDigit;
    }

    void userMenu(User& user) {
        char choice;
        do {
            clearScreen();
            cout << "\n=== USER MENU ===\n"
                 << "1. Change Password\n"
                 << "2. Delete Account\n"
                 << "3. Logout\n"
                 << "Enter choice: ";
            cin >> choice;
            cin.ignore(numeric_limits<streamsize>::max(), '\n');

            switch(choice) {
                case '1': changePassword(user); break;
                case '2': if(deleteAccount(user)) return; break;
                case '3': return;
                default: cout << "Invalid choice!\n";
            }
        } while(true);
    }

public:
    UserAuthenticator() {
        loadUsers();
    }

    void signUP() {
        clearScreen();
        User newUser;

        cout << "\n=== SIGN UP ===\n";
        cout << "Username: ";
        getline(cin, newUser.username);

        for (const User& user : users) {
            if (user.username == newUser.username) {
                cout << "Username already exists!\n";
                return;
            }
        }

        cout << "Email: ";
        getline(cin, newUser.email);
        if (!isValidEmail(newUser.email)) {
            cout << "Invalid email format!\n";
            return;
        }

        for (const User& user : users) {
            if (user.email == newUser.email) {
                cout << "Email already registered!\n";
                return;
            }
        }

        string password;
        cout << "Password: ";
        getline(cin, password);
        if (!isStrongPassword(password)) {
            cout << "Password must be 8+ characters with uppercase, lowercase and numbers!\n";
            return;
        }
        newUser.passwordHash = hashPassword(password);

        cout << "Security Question: ";
        getline(cin, newUser.securityQuestion);
        cout << "Security Answer: ";
        string securityAnswer;
        getline(cin, securityAnswer);
        newUser.securityAnswerHash = hashPassword(securityAnswer);

        users.push_back(newUser);
        saveUsers();
        cout << "Registration successful!\n";
    }

    void login() {
        clearScreen();
        string username, password;

        cout << "\n=== LOGIN ===\n";
        cout << "Username: ";
        getline(cin, username);
        cout << "Password: ";
        getline(cin, password);

        string hashedPassword = hashPassword(password);

        for (User& user : users) {
            if (user.username == username && user.passwordHash == hashedPassword) {
                cout << "\nLogin successful!\n";
                userMenu(user);
                return;
            }
        }
        cout << "Invalid credentials!\n";
    }

    void changePassword(User& targetUser) {
        clearScreen();
        string currentPass, newPass;

        cout << "\n=== CHANGE PASSWORD ===\n";
        cout << "Current password: ";
        getline(cin, currentPass);

        if (hashPassword(currentPass) != targetUser.passwordHash) {
            cout << "Incorrect current password!\n";
            return;
        }

        do {
            cout << "New password: ";
            getline(cin, newPass);
            if (!isStrongPassword(newPass)) {
                cout << "Password must be 8+ characters with uppercase, lowercase and numbers!\n";
            }
        } while (!isStrongPassword(newPass));

        targetUser.passwordHash = hashPassword(newPass);
        saveUsers();
        cout << "Password changed successfully!\n";
    }

    bool deleteAccount(User& targetUser) {
        clearScreen();
        string confirmation;
        cout << "\n=== DELETE ACCOUNT ===\n"
             << "Are you sure? (yes/no): ";
        getline(cin, confirmation);

        if (confirmation == "yes") {
            for (auto it = users.begin(); it != users.end(); ++it) {
                if (it->username == targetUser.username) {
                    users.erase(it);
                    saveUsers();
                    cout << "Account deleted successfully!\n";
                    return true;
                }
            }
        }
        cout << "Account deletion canceled.\n";
        return false;
    }

    void forgotPassword() {
        clearScreen();
        string username, email, securityAnswer;

        cout << "\n=== PASSWORD RECOVERY ===\n";
        cout << "Username: ";
        getline(cin, username);
        cout << "Email: ";
        getline(cin, email);

        for (User& user : users) {
            if (user.username == username && user.email == email) {
                cout << "Security Question: " << user.securityQuestion << endl;
                cout << "Answer: ";
                getline(cin, securityAnswer);

                if (hashPassword(securityAnswer) != user.securityAnswerHash) {
                    cout << "Security answer incorrect!\n";
                    return;
                }

                string newPass, confirmPass;
                do {
                    cout << "New password: ";
                    getline(cin, newPass);
                    cout << "Confirm password: ";
                    getline(cin, confirmPass);

                    if (!isStrongPassword(newPass)) {
                        cout << "Password must be 8+ characters with uppercase, lowercase and numbers!\n";
                    } else if (newPass != confirmPass) {
                        cout << "Passwords don't match!\n";
                    }
                } while (newPass != confirmPass || !isStrongPassword(newPass));

                user.passwordHash = hashPassword(newPass);
                saveUsers();
                cout << "Password reset successfully!\n";
                return;
            }
        }
        cout << "No matching account found!\n";
    }
};

int main() {
    UserAuthenticator auth;
    char choice;

    do {
        cout << "\n=== MAIN MENU ===\n"
             << "1. Login\n"
             << "2. Sign Up\n"
             << "3. Forgot Password\n"
             << "4. Exit\n"
             << "Enter choice: ";
        cin >> choice;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        switch(choice) {
            case '1': auth.login(); break;
            case '2': auth.signUP(); break;
            case '3': auth.forgotPassword(); break;
            case '4': cout << "Exiting...\n"; return 0;
            default: cout << "Invalid choice!\n";
        }
    } while(true);
}
