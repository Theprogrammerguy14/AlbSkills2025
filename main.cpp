#include <bits/stdc++.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <iomanip>
#include <cmath> 
#include <filesystem>
#include <system_error>
#include <chrono>
#include <ctime>
#include <regex>
#include <search.h>

namespace fs = std::filesystem;
using std::error_code;
using json = nlohmann::json;
using namespace std;

string to_lower(string s) {
    transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

string trim_ws(const string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

string hl7_name_to_full(const string& pid5) {
    // HL7 name is DOE^JOHN^MIDDLE
    vector<string> parts;
    string cur;
    for (char c : pid5) {
        if (c == '^') { parts.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    parts.push_back(cur);

    string last = parts.size() > 0 ? parts[0] : "";
    string first = parts.size() > 1 ? parts[1] : "";

    if (!last.empty()) {
        transform(last.begin(), last.end(), last.begin(), ::tolower);
        last[0] = toupper(last[0]);
    }
    if (!first.empty()) {
        transform(first.begin(), first.end(), first.begin(), ::tolower);
        first[0] = toupper(first[0]);
    }

    if (first.empty()) return last;
    if (last.empty()) return first;
    return first + " " + last;
}

string hl7_dob_to_iso(const string& yyyymmdd) {
    if (yyyymmdd.size() < 8) return "";
    return yyyymmdd.substr(0,4) + "-" + yyyymmdd.substr(4,2) + "-" + yyyymmdd.substr(6,2);
}


const int PRIME_CONST = 31; 

string simpleHash(const string& key) {
    const int PRIME_CONST = 31;
    unsigned long long hashValue = 0;
    for (int i = 0; i < key.length(); i++) {
        hashValue = hashValue * PRIME_CONST + key[i];
    }
    stringstream ss;
    ss << hex << hashValue;
    return ss.str();
}

bool check_login(const string& username, const string& password, string& out_role) {
    ifstream in("database.txt");
    if (!in) {
        cout << "Could not open database.txt\n";
        return false;
    }

    json db;
    if (!db.contains("users") || !db["users"].is_array())
        return false;

    string passHash = simpleHash(password);

    for (const auto& u : db["users"]) {
        string uname = u.value("username", "");
        string phash = u.value("passwordHash", "");
        if (username == uname && passHash == phash) {
            out_role = u.value("role", "");
            return true;
        }
    }
    return false;
}
bool username_checker(string& username){
    if(username.empty()) return false;
    if(username.length() < 5){
        cout << "Username must be at least 5 characters long." << endl;
        return false;
    }
    if(username.find(' ') != string::npos){
        cout << "Username must not contain spaces." << endl;
        return false;
    }
    return true;
}
bool password_checker(const string& password) {
    if (password.length() < 8) {
        cout << "Password must be at least 8 characters long." << endl;
        return false;
    }
    if (!any_of(password.begin(), password.end(), ::isupper)) {
        cout << "Password must contain at least one uppercase letter." << endl;
        return false;
    }
    if (!any_of(password.begin(), password.end(), ::islower)) {
        cout << "Password must contain at least one lowercase letter." << endl;
        return false;
    }
    if (!any_of(password.begin(), password.end(), ::isdigit)) {
        cout << "Password must contain at least one digit." << endl;
        return false;
    }
    if (!any_of(password.begin(), password.end(), [](char c) { return ispunct(c); })) {
        cout << "Password must contain at least one special character." << endl;
        return false;
    }
    return true;
}
bool check_roles(string &role){
    if(role == "doctor" || role == "nurse" || role == "admin"){
        return true;
    }
    else{
        cout << "Invalid role! Choose from doctor, nurse, or admin." << endl;
        return false;
    }
}

bool append_user(const string& username,
                               const string& password,
                               const string& role,
                               const string& db_path = "database.txt")
{
    json db;
    {
        fstream in(db_path);
        if (in.good()) {
            try {
                in >> db;
            } catch (...) {
                std::cerr << "ERROR: database.txt is not valid JSON. Aborting to avoid data loss.\n";
                return false;
            }
        } else {
            db = json::object();
        }
    }
    if (!db.contains("users") || !db["users"].is_array()) {
        db["users"] = json::array();
    }
    json new_user = {
        {"username", username},
        {"passwordHash", simpleHash(password)},
        {"role", role}
    };
    db["users"].push_back(new_user);

    {
        ofstream out(db_path);
        if (!out.good()) {
            cerr << "ERROR: Could not open database.txt for writing.\n";
            return false;
        }
        out << setw(4) << db << endl;
    }


    std::cout << "Registration complete!\n";
    return true;
}
static const string SESSION_PATH = "/home/kali/alb_skills/AlbanianSkillsSDC2025/session.json";
static const string AUTHLOG_PATH = "/home/kali/alb_skills/AlbanianSkillsSDC2025/auth.log";

string now_iso8601() {
    using namespace chrono;
    auto t = system_clock::now();
    time_t tt = system_clock::to_time_t(t);
    tm gmt{};
#if defined(_WIN32)
    gmtime_s(&gmt, &tt);        
#else
    gmtime_r(&tt, &gmt);
#endif
    ostringstream os;
    os << std::put_time(&gmt, "%Y-%m-%dT%H:%M:%SZ");
    return os.str();
}

void auth_log(const string& event,
              const string& username,
              const string& details = "") {
    std::ofstream log(AUTHLOG_PATH, std::ios::app);
    if (!log) return;
    log << now_iso8601() << " | " << event << " | user=" << username;
    if (!details.empty()) log << " | " << details;
    log << "\n";
}

bool write_session(const string& username, const string& role) {
    json session = {
        {"username", username},
        {"role", role},
        {"loggedInAt", now_iso8601()}
    };
    ofstream out(SESSION_PATH, ios::trunc);
    if (!out) return false;
    out << setw(4) << session << "\n";
    return (bool)out;
}
bool read_session(json& session) {
    ifstream in(SESSION_PATH);
    if (!in.good()) return false;
    try { in >> session; }
    catch (...) { return false; }
    return session.contains("username") && session.contains("role");
}

bool is_authenticated(string& username_out, string& role_out) {
    json s;
    if (!read_session(s)) return false;
    username_out = s.value("username", "");
    role_out = s.value("role", "");
    return !username_out.empty() && !role_out.empty();
}

void logout_session() {
    remove(SESSION_PATH.c_str());
}

bool safe_load_db(const string& path, json& db) {
    ifstream in(path);
    if (!in.good()) {
        db = json::object();
        db["users"] = json::array();
        db["patients"] = json::array();
        return true;
    }
    try { in >> db; }
    catch (...) {
        db = json::object();
        db["users"] = json::array();
        db["patients"] = json::array();
        return true;
    }
    if (!db.contains("users") || !db["users"].is_array()) db["users"] = json::array();
    if (!db.contains("patients") || !db["patients"].is_array()) db["patients"] = json::array();
    return true;
}

bool safe_save_db(const string& path, const json& db) {
    ofstream out(path, ios::trunc);
    if (!out.good()) return false;
    out << setw(4) << db << "\n";
    return (bool)out;
}

string make_uuid_like() {
    static random_device rd;
    static mt19937_64 gen(rd());
    auto r1 = gen(), r2 = gen();
    stringstream ss;
    ss << hex << std::setfill('0')
       << setw(8)  << (uint32_t)(r1 >> 32) << "-"
       << setw(4)  << (uint16_t)(r1 >> 16) << "-"
       << setw(4)  << (uint16_t)(r1)       << "-"
       << setw(4)  << (uint16_t)(r2 >> 48) << "-"
       << setw(12) << (uint64_t)(r2 & 0x0000FFFFFFFFFFFFULL);
    return ss.str();
}

bool valid_mrn(const std::string& mrn) {
    if (mrn.empty()) return false;
    static const std::regex rx("^[A-Za-z0-9_-]+$");
    return std::regex_match(mrn, rx);
}

bool valid_date_iso(const std::string& d) {
    static const std::regex rx("^\\d{4}-\\d{2}-\\d{2}$");
    if (!std::regex_match(d, rx)) return false;
    int y = stoi(d.substr(0,4));
    int m = stoi(d.substr(5,2));
    int day = stoi(d.substr(8,2));
    if (m < 1 || m > 12) return false;
    if (day < 1 || day > 31) return false; 
    return true;
}

string jget_str(const json& j, const string& key) {
    auto it = j.find(key);
    if (it == j.end() || it->is_null() || !it->is_string()) return "";
    return it->get<string>();
}

void create_patient(){
    string curUser, curRole;
    if (!is_authenticated(curUser, curRole)) {
        cout << "ERROR: User not authenticated. Please login first.\n";
        return;
    }
    if (curRole != "doctor") {
        cout << "ERROR: Permission denied. Only doctors can create new patients.\n";
        return;
    }
    string name;
    string date_of_birth;
    string MRN;
    string Patient_ID;
    cout << "Enter Patient Name: ";
    cin >> name;
    if (name.empty()) {
        cout << "ERROR: Patient name cannot be empty.\n";
        return;
    }
    cout << "Enter Date of Birth (YYYY-MM-DD): ";
    cin >> date_of_birth;
     if (!valid_date_iso(date_of_birth)) {
        cout << "ERROR: Invalid date format. Expected YYYY-MM-DD.\n";
        return;
    }
    cout << "Enter Medical Record Number (MRN): ";
    cin >> MRN;
    if (MRN.empty()) {
        cout << "ERROR: MRN cannot be empty.\n";
        return;
    }
    cout << "Enter Patient ID: ";
    cin >> Patient_ID;
    if (Patient_ID.empty()) {
        cout << "ERROR: Patient ID cannot be empty.\n";
        return;
    }

    json db;
    safe_load_db("database.txt", db);

    for (const auto& p : db["patients"]) {
        if (p.value("mrn", "") == MRN) {
            cout << "ERROR: MRN already exists. Please use a different MRN.\n";
            return;
        }
    }

   
    const string pid = make_uuid_like();
    json patient = {
        {"patientId",      Patient_ID},
        {"mrn",            MRN},
        {"name",           name},
        {"dateOfBirth",    date_of_birth},                
        {"assignedDoctor", curUser},            
        {"transmissions",  json::array()}       
    };

    db["patients"].push_back(patient);

    if (!safe_save_db("database.txt", db)) {
        cout << "ERROR: Failed to save patient to database.\n";
        return;
    }

    cout << "SUCCESS: Patient created successfully. Patient ID: "
              << Patient_ID << ". Assigned to: " << curUser << "\n";
}

bool parse_hl7_file(const string& path, json& out_json, string& out_report_id, string& err) {
    ifstream f(path);
    if (!f.good()) { err = "ERROR: File not found: " + path; return false; }

    string content((istreambuf_iterator<char>(f)), istreambuf_iterator<char>());
    if (content.empty()) { err = "ERROR: File is empty or unreadable."; return false; }

    auto trim = [](const string& s) {
        size_t a = s.find_first_not_of(" \t\r\n");
        if (a == string::npos) return string();
        size_t b = s.find_last_not_of(" \t\r\n");
        return s.substr(a, b - a + 1);
    };
    auto split = [](const string& s, char delim) {
        vector<string> out; string cur;
        for (char c : s) { if (c == delim) { out.push_back(cur); cur.clear(); } else cur.push_back(c); }
        out.push_back(cur); return out;
    };

    for (size_t pos = 0; (pos = content.find("\r\n", pos)) != string::npos; ) content.replace(pos, 2, "\n");
    for (char& c : content) if (c == '\r') c = '\n';

    vector<string> lines;
    { string line; stringstream ss(content);
      while (getline(ss, line, '\n')) { line = trim(line); if (!line.empty()) lines.push_back(line); } }
    if (lines.empty()) { err = "ERROR: Failed to parse HL7 file. Invalid format."; return false; }

    bool sawPID = false, sawOBX = false;
    string reportDate, messageType;
    string pid_mrn, pid_name, pid_dob;
    vector<json> observations;
    vector<string> warnings;

    for (size_t i = 0; i < lines.size(); ++i) {
        const string& line = lines[i];
        try {
            vector<string> fields = split(line, '|');
            if (fields.empty()) continue;

            const string seg = fields[0];

            if (seg == "MSH") {
                if (fields.size() > 6) reportDate  = fields[6];
                if (fields.size() > 8) messageType = fields[8];
            } else if (seg == "PID") {
                sawPID = true;
                if (fields.size() > 2) {
                    string pid3 = fields[2];
                    auto comps = split(pid3, '^');
                    pid_mrn = comps.empty() ? "" : comps[0];
                }
                if (fields.size() > 4) pid_name = fields[4];
                if (fields.size() > 6) pid_dob  = fields[6];
            } else if (seg == "OBX") {
                sawOBX = true;
                string code, val, unit, ref, abn;
                if (fields.size() > 2) {
                    auto comps = split(fields[2], '^');
                    code = comps.empty() ? "" : comps[0];
                }
                if (fields.size() > 4) val  = fields[4];
                if (fields.size() > 5) unit = fields[5];
                if (fields.size() > 6) ref  = fields[6];
                if (fields.size() > 7) abn  = fields[7];

                observations.push_back(json{
                    {"code",           code.empty() ? nullptr : json(code)},
                    {"value",          val.empty()  ? nullptr : json(val)},
                    {"unit",           unit.empty() ? nullptr : json(unit)},
                    {"referenceRange", ref.empty()  ? nullptr : json(ref)},
                    {"abnormalFlag",   abn.empty()  ? nullptr : json(abn)}
                });
            }
        } catch (const std::exception& ex) {
            stringstream ss; ss << "Warning: Failed to parse line " << (i+1) << ": " << ex.what();
            warnings.push_back(ss.str());
            continue;
        } catch (...) {
            stringstream ss; ss << "Warning: Unknown parse error at line " << (i+1);
            warnings.push_back(ss.str());
            continue;
        }
    }

    if (!sawPID) warnings.push_back("Missing PID segment");
    if (!sawOBX) warnings.push_back("No OBX segments found");

    out_report_id = make_uuid_like();

    out_json = {
        {"reportId",    out_report_id},
        {"reportDate",  reportDate},
        {"messageType", messageType},
        {"observations", observations},
        {"patientIdentifiers", {
            {"mrn",        pid_mrn.empty()  ? nullptr : json(pid_mrn)},
            {"name",       pid_name.empty() ? nullptr : json(pid_name)},
            {"dateOfBirth",pid_dob.empty()  ? nullptr : json(pid_dob)}
        }},
        {"parseStatus", (warnings.empty() ? "ok" : "partial")},
        {"parseWarnings", warnings}
    };
    return true;
}

void upload_report(){
    string curUser, curRole;
    if (!is_authenticated(curUser, curRole)) {
        cout << "ERROR: User not authenticated. Please login first.\n";
        return;
    }
    if (curRole != "nurse" && curRole != "doctor") {
        cout << "ERROR: Permission denied. Only doctors and nurses can upload reports.\n";
        return;
    }
    string path;
    cout << "Enter file path: ";
    cin.ignore();
    getline(cin, path);

    size_t a = path.find_first_not_of(" \t\r\n");
    size_t b = path.find_last_not_of(" \t\r\n");
    path = (a==string::npos) ? "" : path.substr(a, b-a+1);

    string lower = path; transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.size() < 4 || lower.substr(lower.size()-4) != ".hl7") {
        cout << "ERROR: Invalid file format. Expected .hl7 file.\n";
        return;
    }

    cout << "Processing file: " << path << "\n";
    json parsed;
    string reportId, err;
    if (!parse_hl7_file(path, parsed, reportId, err)) {
        cout << err << "\n";
        return;
    }

    cout << parsed.dump(2) << "\n";
    cout << "SUCCESS: Report parsed successfully. Report ID: "
         << reportId << ". Data extracted and ready for processing.\n";

    cout << "Matching to patient...\n";

    string mrn      = jget_str(parsed["patientIdentifiers"], "mrn");
    string pid_name = jget_str(parsed["patientIdentifiers"], "name");
    string pid_dob  = jget_str(parsed["patientIdentifiers"], "dateOfBirth");

    json db;
    safe_load_db("database.txt", db);

    int matched_idx = -1;

    if (!mrn.empty()) {
        for (int i = 0; i < (int)db["patients"].size(); ++i) {
            if (db["patients"][i].value("mrn", "") == mrn) {
                matched_idx = i;
                break;
            }
        }
    }

    if (matched_idx < 0 && !pid_name.empty() && !pid_dob.empty()) {
        for (int i = 0; i < (int)db["patients"].size(); ++i) {
            if (db["patients"][i].value("name", "") == pid_name && 
                db["patients"][i].value("dateOfBirth", "") == pid_dob) {
                matched_idx = i;
                break;
            }
        }
    }

    cout << "Patient found!" << endl;

    cout << "Found patient: " << db["patients"][matched_idx].value("name", "Unknown") 
         << " (MRN: " << db["patients"][matched_idx].value("mrn", "N/A") << ")\n";
    cout << "Storing transmission...\n";

    if (!db["patients"][matched_idx].contains("transmissions") || 
        !db["patients"][matched_idx]["transmissions"].is_array()) {
        db["patients"][matched_idx]["transmissions"] = json::array();
    }

    db["patients"][matched_idx]["transmissions"].push_back(parsed);


    if (!safe_save_db("database.txt", db)) {
        cout << "ERROR: Failed to save transmission to database.\n";
        return;
    }

    cout << "SUCCESS: Report matched and stored for patient "
         << db["patients"][matched_idx].value("name", "Unknown")
         << " (MRN: " << db["patients"][matched_idx].value("mrn", "N/A") << ")\n";
}

void match_reports_by_MRN(){
    string curUser, curRole;
    if (!is_authenticated(curUser, curRole)) {
        cout << "ERROR: User not authenticated. Please login first.\n";
        return;
    }
    if (curRole != "doctor") {
        cout << "ERROR: Permission denied. Only doctors can match reports by MRN.\n";
        return;
    }
    cout << "Enter Medical Record Number (MRN) to match reports: ";
    string mrn;
    cin >> mrn;
    if (mrn.empty()) {
        cout << "ERROR: MRN cannot be empty.\n";
        return;
    }

    json db;
    safe_load_db("database.txt", db);

    int matched_idx = -1;

    for (int i = 0; i < (int)db["patients"].size(); ++i) {
        if (db["patients"][i].value("mrn", "") == mrn) {
            matched_idx = i;
            break;
        }
    }

    if (matched_idx < 0) {
        cout << "ERROR: No matching patient found for MRN: " << mrn << "\n";
        return;
    }

    cout << "Found patient: " << db["patients"][matched_idx].value("name", "Unknown") 
         << " (MRN: " << db["patients"][matched_idx].value("mrn", "N/A") << ")\n";
    cout << "Reports for this patient:\n";

    const auto& transmissions = db["patients"][matched_idx]["transmissions"];
    for (const auto& t : transmissions) {
        cout << t.dump(2) << "\n";
        cout << "----------------------------------------\n";
    }
}
void view_patients(){
    json db;
    safe_load_db("database.txt", db);
    cout << "List of Patients:\n";
    if(db["patients"].empty()){
        cout << "No patients found.\n";
        return;
    }
    for (const auto& p : db["patients"]) {
        cout << "Patient ID: " << p.value("patientId", "N/A") << "\n";
        cout << "Name: " << p.value("name", "N/A") << "\n";
        cout << "Date of Birth: " << p.value("dateOfBirth", "N/A") << "\n";
        cout << "MRN: " << p.value("mrn", "N/A") << "\n";
        cout << "Assigned Doctor: " << p.value("assignedDoctor", "N/A") << "\n";
        cout << "----------------------------------------\n";
    }
}

void view_recent_transmissions(){
    json db;
    safe_load_db("database.txt", db);
    cout << "\n=== Recent Transmissions ===\n";
    
    for (const auto& p : db["patients"]) {
        if(!p.contains("transmissions")){
            cout << "No transmissions found for patient: " << p.value("name", "N/A") << "\n";
            continue;
        }
        const auto& transmissions = p["transmissions"];
        if (!transmissions.is_array() || transmissions.empty()) continue;
        
        for (const auto& t : transmissions) {
            cout << "\n--- Transmission ---\n";
            cout << "Report ID: " << jget_str(t, "reportId") << "\n";
            cout << "Report Date: " << jget_str(t, "reportDate") << "\n";
            cout << "Message Type: " << jget_str(t, "messageType") << "\n";
            
            cout << "\nPatient Identifiers:\n";
            if (t.contains("patientIdentifiers") && t["patientIdentifiers"].is_object()) {
                string mrn = jget_str(t["patientIdentifiers"], "mrn");
                string name = jget_str(t["patientIdentifiers"], "name");
                string dob = jget_str(t["patientIdentifiers"], "dateOfBirth");
                
                cout << "  MRN: " << (mrn.empty() ? "N/A" : mrn) << "\n";
                cout << "  Name: " << (name.empty() ? "N/A" : name) << "\n";
                cout << "  Date of Birth: " << (dob.empty() ? "N/A" : dob) << "\n";
            }
            
            cout << "\nObservations:\n";
            if (t.contains("observations") && t["observations"].is_array()) {
                const auto& obs_array = t["observations"];
                for (size_t i = 0; i < obs_array.size(); ++i) {
                    const auto& observe = obs_array[i];
                    cout << "  [" << (i + 1) << "]\n";
                    cout << "    Code: " << jget_str(observe, "code") << "\n";
                    cout << "    Value: " << jget_str(observe, "value") << "\n";
                    cout << "    Unit: " << jget_str(observe, "unit") << "\n";
                    cout << "    Reference Range: " << jget_str(observe, "referenceRange") << "\n";
                    cout << "    Abnormal Flag: " << jget_str(observe, "abnormalFlag") << "\n";
                }
            }
            cout << "----------------------------------------\n";
        }
    }
}
void dashboard(){
    string curUser, curRole;
    if (!is_authenticated(curUser, curRole)) {
        cout << "ERROR: User not authenticated. Please login first.\n";
        return;
    }
    cout << "Welcome to the dashboard, " << curUser << " (" << curRole << ")\n";
    if (curRole == "doctor") {
        cout << "1. View Patients\n";
        cout << "2. View recent transmissions\n";
        cout << "3. Exit" << endl;
        int choice;
        cin >> choice;
        if (choice == 1) {
            view_patients();
        } else if (choice == 2) {
            view_recent_transmissions();
        } else {
            return;
        }
    } else if (curRole == "nurse") {
       cout << "Permission denied. Nurses have no access in the dashboard.\n";
    }
}

void search(){
        
}
int main(){
    ifstream input_file;
    input_file.open("database.txt");
   string image =
        "\n"
        "                                        @@@                         @@@          @  @@@ @@@      \n"
        "                                         @@@  @                  @@@ @@@         @@@  @           \n"
        "          @                              @@@  @                               @  @@@  @          \n"
        " @@@  @      @@@         @@@ @@@         @@@  @                  @@@ @@@     @@@ @@@ @@@ @@@     @@@ @@@ @@@ @@@ @@@  \n"
        "  @              @@@         @@@         @@@  @                  @@@ @@@         @@@             @@@             @@@   \n"
        "                 @@@         @@@         @@@  @                  @@@ @@@         @@@         @@@ @@@ @@@ @@@ @@@ @@@     \n"
        " @@@             @@@         @@@         @@@  @                  @@@ @@@         @@@         @@@ @@@                      \n"
        "     @@@ @@@ @@@ @@@         @@@         @@@  @                  @@@ @@@         @@@             @@@  @          @@@      \n"
        "             @@@             @@@         @@@ @@@ @@@ @@@ @@@     @@@ @@@         @@@              @  @@@ @@@ @@@ @@@      \n"
        "             @       \n"
        "         @@@          \n";    
    cout << image;                                         
    cout << "*********************************************************WELCOME TO 91LIFE*********************************************" << endl;
    cout << "Select action: \n"
    "1.Register \n"
    "2.Login\n";
    int action_input;
    string user_key = "91Life_Staff_Access?!";
    string secret_key;
    cin >> action_input;
    string username_input_login;
    string password_input_login;
    string username_input_register;
    string password_input_register;
    string role;
    if(action_input == 1){
        cout << "Enter secret key to register: ";
        cin >> secret_key;
        if(secret_key == user_key){
            cout << "Secret key is correct!" << endl;

            cout << "Enter Username: ";
            cin >> username_input_register;
            if(!username_checker(username_input_register)){
                cout << "Registration failed due to invalid username." << endl;
                return 0;
            }

            cout << "Enter Password: ";
            cin >> password_input_register;
            if(!password_checker(password_input_register)){
                cout << "Recheck the password requirements and try again." << endl;
            }   

            cout << "Enter Role (doctor/nurse/admin): ";
            cin >> role;
            if(!check_roles(role)){
                cout << "Registration failed due to invalid role." << endl;
                return 0;
            }
            if(check_login(username_input_register, password_input_register, role)){
                cout << "User already exists!" << endl;
            }
            else{
                if(append_user(username_input_register, password_input_register, role)){
                    return 0;
                }
                else{
                    cout << "Failed to register user due to a database error." << endl;
                }
            }
        }

        else{
            cout << "Secret key is incorrect!"; 
            
        }
    }
    else if (action_input == 2) {
    cout << "Enter secret Key: ";
    cin >> secret_key;
    if(secret_key != user_key){
        cout << "Secret key is incorrect!";
        return 0;
    }
    cout << "Enter username: " << endl;
    cin >> username_input_login;
    if (!username_checker(username_input_login)) {
        cout << "Login failed due to invalid username." << endl;
        return 0;
    }

    cout << "Enter password: " << endl;
    cin >> password_input_login;

    cout << "Enter role (doctor/nurse/admin): ";
    cin >> role;
    if (!check_roles(role)) {
        cout << "Login failed due to invalid role." << endl;
        return 0;
    }

    ifstream in("database.txt");
    if (!in.good()) {
        cout << "ERROR: Could not open database.txt" << endl;
        return 0;
    }

    json db;
    try {
        in >> db;
    } catch (...) {
        cout << "ERROR: database.txt is corrupted or empty." << endl;
        return 0;
    }

    if (!db.contains("users") || !db["users"].is_array()) {
        cout << "ERROR: Invalid database format." << endl;
        return 0;
    }
    string hashedInput = simpleHash(password_input_login);

    bool found = false;
    for (auto& user : db["users"]) {
        string uname = user.value("username", "");
        string phash = user.value("passwordHash", "");
        string urole = user.value("role", "");

        if (uname == username_input_login &&
            phash == hashedInput &&
            urole == role) {
            found = true;
            break;
        }
    }
     if (found) {
        if (!write_session(username_input_login, role)) {
            cout << "ERROR: Could not write session file.\n";
            auth_log("login_fail", username_input_login, "session_write_failed");
            return 0;
        }
        cout << "Login successful!" << endl;
        auth_log("login_success", username_input_login);
    } else {
        cout << "Login failed. Invalid credentials." << endl;
        auth_log("login_fail", username_input_login, "bad_credentials");
    }

    if(found){
        cout << "1.Create-patient" << endl;
        cout << "2.upload report" << endl;
        cout << "3.Dashboard" << endl;
        cout << "4.search-patient" << endl;
        cin >> action_input;
        if(action_input == 1){
            cout << "Creating patient..." << endl;
            create_patient();
        }
        if(action_input == 2){
            cout << "Uploading report..." << endl;
            upload_report();
            cout << "Searching for matches... " << endl;
            match_reports_by_MRN();
        }
        if(action_input == 3){
            cout << "Accessing dashboard..." << endl;
            dashboard();
        }
        if(action_input == 4){
            cout << "Searching for patient reports..." << endl;
            search();
        }
}
}
}
