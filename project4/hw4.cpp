#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <cstring>
#include <sstream>
#include <cerrno>
#include <climits>
#include <elf.h>
#include <map>
#include <vector>
#include <unistd.h>
#include <assert.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <capstone/capstone.h>

#define SETW    21
#define MAX_CMD 10
#define NOTLOAD 0
#define LOADED  1
#define RUNNING 2

#define ERR_CHECK(error) \
		if (errno != 0) { \
			cerr << "Error: " << (error) << endl; \
			cerr << "System error (" << errno << "): " << strerror(errno) << endl; \
			exit(EXIT_FAILURE); \
		}
#define ERR_QUIT(error) \
		cerr << "Error: " << (error) << endl; \
		if (errno != 0) { \
			cerr << "System error (" << errno << "): " << strerror(errno) << endl; \
			exit(EXIT_FAILURE); \
		}

using namespace std;

bool catchbp = false;
int state = NOTLOAD;
ifstream script;

void disasm(string);
void set(string, unsigned long long);
void si();
void dump(string);
void start();
void get(string);
void getregs();

struct Breakpoint {
	uint8_t byte;
	uint64_t addr;
	Breakpoint *next;
	Breakpoint(uint8_t byte, uint64_t addr, Breakpoint* next = nullptr) : byte(byte), addr(addr), next(next) {}
}*bpList = nullptr;

struct Program {
	pid_t child;
	string path;
	ifstream file;
	struct user_regs_struct regs;
	unsigned long long textBeg, textEnd;
}p;

map<string, int> regMap = {
	{"r15", 0},
	{"r14", 1},
	{"r13", 2},
	{"r12", 3},
	{"rbp", 4},
	{"rbx", 5},
	{"r11", 6},
	{"r10", 7},
	{"r9",  8},
	{"r8",  9},
	{"rax", 10},
	{"rcx", 11},
	{"rdx", 12},
	{"rsi", 13},
	{"rdi", 14},
	{"rip", 16},
	{"eflags", 18},
	{"rsp", 19},
};

int checkstat(int stat) {
	switch (stat){
		case LOADED:
			if (state != LOADED) {
				if (p.path.empty())
					cerr << "** there is no program to be loaded." << endl;
				else
					cerr << "** program \'" << p.path << "\' have not loaded." << endl;
				return -1;
			}
			break;
		case RUNNING:
			if (state != RUNNING) {
				cerr << "** program \'" << p.path << "\' is not running." << endl;
				return -1;
			}
	}
	return 0;
}

Breakpoint* findbp(unsigned long long address) {
	Breakpoint *tmp = bpList;
	while (tmp != nullptr) {
		if (tmp->addr == address) {
			return tmp;
		}
		tmp = tmp->next;
	}
	return nullptr;
}

uint8_t findbyte(unsigned long long address) {
	Breakpoint *tmp = bpList;
	while (tmp != nullptr) {
		if (tmp->addr == address) {
			return tmp->byte;
		}
		tmp = tmp->next;
	}
	return 0;
}

long peektext(unsigned long long addr) {
	errno = 0;
	long ret = ptrace(PTRACE_PEEKTEXT, p.child, addr, 0);
	ERR_CHECK("PTRACE(PEEKTEXT)");
	return ret;
}

long poketext(unsigned long long addr, uint8_t new_code) {
	long ori_code = peektext(addr);
	if (ptrace(PTRACE_POKETEXT, p.child, addr, (ori_code & 0xffffffffffffff00) | new_code) < 0) ERR_QUIT("PTRACE(POKETEXT)");
	return ori_code;
}

void splitString(const string &str, string &firstPart, string &secondPart) {
	size_t pos = str.find('-');
	if (pos != string::npos) {
		firstPart  = str.substr(0, pos);
		secondPart = str.substr(pos + 1);
	}
	else {
		firstPart = str;
		secondPart = "";
	}
}

string getbytes(const cs_insn &insn) {
	stringstream ss;
	for (size_t i = 0; i < 5; i++) {
		if (i < insn.size) {
			ss << hex << setw(2) << setfill('0') << (int)insn.bytes[i] << " ";
		}
		else {
			ss << "   ";
		}
	}
	return ss.str();
}

unsigned long long strToULL(const string &str) {
	char *end;
	unsigned long long int value = strtoull(str.c_str(), &end, 0);

	if (end == str.c_str()) {
		throw invalid_argument("Invalid input string");
	}
	if (*end != '\0') {
		throw invalid_argument("Extra characters found after number");
	}
	if (value == ULLONG_MAX && errno == ERANGE) {
		throw out_of_range("Value out of range for unsigned long long int");
	}
	return value;
}

void checkbp(unsigned long long rip) {
	Breakpoint *match = findbp(rip);
	if (match != nullptr) {
		cout << "matched" << endl;
		poketext(rip, match->byte);
		if (ptrace(PTRACE_SINGLESTEP, p.child, 0, 0) < 0) ERR_QUIT("ptrace(SINGLESTEP)");
		int status;
		waitpid(p.child, &status, 0);
		poketext(match->addr, 0xcc);
	}
	return;
	// Breakpoint *tmp = bpList;
	// while (tmp != nullptr) {
	// 	if (tmp->addr == rip) {
	// 		// set("rip", rip);
	// 		poketext(rip, tmp->byte);
	// 		if (ptrace(PTRACE_SINGLESTEP, p.child, 0, 0) < 0) ERR_QUIT("ptrace(SINGLESTEP)");
	// 		int status;
	// 		waitpid(p.child, &status, 0);
	// 		// si();
	// 		poketext(tmp->addr, 0xcc);
	// 		return;
	// 	}
	// 	tmp = tmp->next;
	// }
}

int capstone(unsigned long long &rip) {
	/* read code */
	long ret = peektext(rip);
	uint8_t *ptr = (uint8_t*) &ret;
	for (int j = 0; j < 8; j++) {
		Breakpoint *match;
		if (ptr[j] == 0xcc) {
			match = findbp(rip + j);
			ptr[j] = match->byte;
			// ptr[j] = findbyte(rip + j);
		}
	}
	vector<uint8_t> code;
	code.insert(code.end(), ptr, ptr + sizeof(ret));

	/* disasm code */
	csh handle = 0;
	cs_insn *insn;
	size_t count;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) ERR_QUIT("CS_OPEN");

	if ((count = cs_disasm(handle, code.data(), code.size(), rip, 1, &insn)) > 0) {
		for (size_t j = 0; j < count; j++) {
			if (insn[j].address >= p.textEnd || insn[j].address < p.textBeg) {
				cerr << "** the address is out of the range of the text segment (0x" << hex << p.textBeg << " - 0x" << p.textEnd << ")" << endl;
				cs_free(insn, count);
				cs_close(&handle);
				return -1;
			}
			cout << hex << setw(10) << insn[j].address << ": " << getbytes(insn[j]);
			cout << setw(15) << setfill(' ') << insn[j].mnemonic << "   " << insn[j].op_str << endl;
			rip += insn[j].size;
		}
		code.clear();
		cs_free(insn, count);
	}
	else {
		cs_close(&handle);
		ERR_QUIT("CS_DISASM");
		return -1;
	}
	cs_close(&handle);
	return 0;
}

void wait() {
	int status;
	waitpid(p.child, &status, 0);
	if (WIFSTOPPED(status)) {
		if (ptrace(PTRACE_GETREGS, p.child, NULL, &p.regs) < 0) ERR_QUIT("ptrace(GETREGS)");
		Breakpoint *match = findbp(p.regs.rip - 1);
		cout << hex << p.regs.rip << endl;
		if (match != nullptr) 
		{	catchbp = true;
			cout << "matched" << endl;}
		// Breakpoint *tmp = bpList;
		// while (tmp != nullptr) {
		// 	if (tmp->addr == p.regs.rip - 1) {m
		// 		catchbp = true;
		// 	}
		// 	tmp = tmp->next;
		// }

		// int signal = WSTOPSIG(status);
		if (catchbp) {
			cout << "** breakpoint @    ";
			// if (ptrace(PTRACE_GETREGS, p.child, NULL, &p.regs) < 0) ERR_QUIT("ptrace(GETREGS)");
			p.regs.rip--;
			set("rip", p.regs.rip);
			capstone(p.regs.rip);
			catchbp = false;
		}
	}
	else if (WIFEXITED(status)) {
		cout << "** child process " << dec << p.child << " terminiated normally (code " << WTERMSIG(status) << ")" << endl;
		state = LOADED;
	}
}

void breakpoint(unsigned long long addr) {
	if (checkstat(RUNNING) < 0) return;

	long ret = poketext(addr, 0xcc);
	Breakpoint *newbp = new Breakpoint(ret, addr);
	if (bpList == nullptr)
		bpList = newbp;
	else {
		Breakpoint *last = bpList;
		while (last->next && last->addr != addr) {
            last = last->next;
        }
        if (last->addr == addr) {
            cerr << "** the same address already has a breakpoint." << endl;
            delete newbp;
            return;
        }
		last->next = newbp;
	}
}

void cont() {
	if (checkstat(RUNNING) < 0) return;

	if (ptrace(PTRACE_GETREGS, p.child, NULL, &p.regs) < 0) ERR_QUIT("ptrace(GETREGS)");
	checkbp(p.regs.rip);
	if (ptrace(PTRACE_CONT, p.child, 0, 0) < 0) ERR_QUIT("ptrace(CONT)");
	wait();
}

void deletebp(size_t index) {
	if (checkstat(RUNNING) < 0) return;

	long ret;
	Breakpoint *match = bpList, *del;
	if (index == 0) {
		if (bpList == nullptr) {
			cerr << "** breakpoint 0 does not exist." << endl;
			return;
		}
		bpList = match->next;
		del = match;
	}
	else {
		for (size_t i = 0; i < index - 1; i++) {
			if (!match) {
				cerr << "** breakpoint " << index << " does not exist." << endl;
				return;
			}
			match = match->next;
		}
		del = match->next;
		match->next = match->next->next;
	}
	poketext(del->addr, del->byte);
	// ret = peektext(match->addr);
	// cout << hex << ret << endl;
	// if (ptrace(PTRACE_POKETEXT, p.child, del->addr, (ret & 0xffffffffffffff00) | del->byte) < 0) ERR_QUIT("PTRACE(POKETEXT)");
	delete(del);

	cout << "** breakpoint " << index << " deleted." << endl;
}

void disasm(string addr) {
	if (checkstat(RUNNING) < 0) return;

	unsigned long long rip = strToULL(addr);
	for (int i = 0; i < 10; i++) {
		if (capstone(rip) < 0)
			break;
	}
}

void dump(string addr) {
	if (checkstat(RUNNING) < 0) return;

	unsigned long long rip = strToULL(addr);
	for(int line = 0; line < 5; line++) {
		string s;

		cout << setw(10) << hex << rip << ": ";
		for (int i = 0; i < 2; i++) {
			long ret = peektext(rip);
			unsigned char *ptr = (unsigned char*) &ret;
			for (int j = 0; j < 8; j++) {
				printf("%2.2x ", ptr[j]);
			}
			for (int j = 0; j < 8; j++) {
				s += isprint(ptr[j]) ? ptr[j] : '.';
			}
			rip += 8;
		}
		cout << " |" << s << "|" << endl;
	}
}

void get(string reg) {
	if (checkstat(RUNNING) < 0) return;

	errno = 0;
	unsigned long long reg_v = ptrace(PTRACE_PEEKUSER, p.child, sizeof(long) * regMap[reg], NULL);
	ERR_CHECK("PTRACE(PEEKUSER)");
	cout << reg << " = " << dec << reg_v << " (0x" << hex << reg_v << ")" << endl;
	return;
}

void getregs() {
	if (checkstat(RUNNING) < 0) return;

	if (ptrace(PTRACE_GETREGS, p.child, NULL, &p.regs) < 0) ERR_QUIT("ptrace(GETREGS)");
	cout << "RAX " << left << setw(SETW) << dec << p.regs.rax << "RBX " << left << setw(SETW) << p.regs.rbx << "RCX " << left << setw(SETW) << p.regs.rdx << "RDX " << left << setw(SETW) << p.regs.rdx << endl;
	cout << "R8  " << left << setw(SETW) << p.regs.r8  << "R9  " << left << setw(SETW) << p.regs.r9  << "R10 " << left << setw(SETW) << p.regs.r10 << "R11 " << left << setw(SETW) << p.regs.r11 << endl;
	cout << "RDI " << left << setw(SETW) << p.regs.rdi << "RSI " << left << setw(SETW) << p.regs.rsi << "RBP " << left << setw(SETW) << p.regs.rbp << "RSP " << left << setw(SETW) << hex << p.regs.rsp << endl;
	cout << "RIP " << left << setw(SETW) << hex << p.regs.rip << "FLAGS " << setfill('0') << setw(SETW - 2) << p.regs.rbx << setfill(' ') << right << endl;
}

void help() {
	cout << "[Help message:]\n"
			"- break {instruction-address}: add a break point\n"
			"- cont: continue execution\n"
			"- delete {break-point-id}: remove a break point\n"
			"- disasm addr: disassemble instructions in a file or a memory region\n"
			"- dump addr: dump memory content\n"
			"- exit: terminate the debugger\n"
			"- get reg: get a single value from a register\n"
			"- getregs: show registers\n"
			"- help: show this message\n"
			"- list: list break points\n"
			"- load {path/to/a/program}: load a program\n"
			"- run: run the program\n"
			"- vmmap: show memory layout\n"
			"- set reg val: get a single value to a register\n"
			"- si: step into instruction\n"
			"- start: start the program and stop at the first instruction" << endl;
}

void list() {
	Breakpoint *tmp = bpList;
	if (!bpList) return;
	for(int i = 0; tmp; i++) {
		cout << setw(5) << i << ": " << setw(8) << hex << tmp->addr << endl;
		tmp = tmp->next;
	}
}

void load() {
	if (state == LOADED) {
		cerr << "** program \'" << p.path << "\' is already loaded." << endl;
		return;
	}

	Elf64_Ehdr hdr;
	p.file.open(p.path);
	p.file.read((char*)&hdr, sizeof(Elf64_Ehdr));
	cout << "** program \'" << p.path << "\' loaded. entry point 0x" << hex << hdr.e_entry << endl;

	Elf64_Shdr shdr[hdr.e_shnum];
	p.file.seekg(hdr.e_shoff);
	p.file.read((char*)&shdr, sizeof(shdr));

	Elf64_Shdr strtab = shdr[hdr.e_shstrndx];
	char table[strtab.sh_size];
	p.file.seekg(strtab.sh_offset);
	p.file.read(table, strtab.sh_size);

	for (const auto &sh : shdr) {
		if (strcmp(&table[sh.sh_name], ".text") == 0) {
			p.textBeg = sh.sh_addr;
			p.textEnd = p.textBeg + sh.sh_size;
		}
	}
	state = LOADED;
}

void run() {
	if (state == NOTLOAD) {
		cerr << "** program \'" << p.path << "\' have not loaded yet." << endl;
		return;
	}
	start();
	cont();
}

void vmmap() {
	if (checkstat(RUNNING) < 0) return;

	string s;
	ifstream maps("/proc/" + to_string(p.child) + "/maps");
	while (getline(maps, s)) {
		stringstream ss(s);
		string address, permissions, inode, pathname, unuse, beg, end;
		ss >> address >> permissions >> unuse >> unuse >> inode >> pathname;

		splitString(address, beg, end);
		cout << setw(16) << setfill('0') << beg << "-" << setw(16) << end << " " << permissions.substr(0, 3) << " " << setfill(' ') << setw(16) << left << inode << " " << pathname << right << endl;
	}
	maps.close();
}

void set(string reg, unsigned long long value) {
	if (checkstat(RUNNING) < 0) return;

	if (ptrace(PTRACE_POKEUSER, p.child, sizeof(long) * regMap[reg], value) < 0) ERR_QUIT("ptrace(POKEUSER)");
}

void si() {
	if (checkstat(RUNNING) < 0) return;

	if (ptrace(PTRACE_GETREGS, p.child, NULL, &p.regs) < 0) ERR_QUIT("ptrace(GETREGS)");
	cout << hex << p.regs.rip << endl;
	checkbp(p.regs.rip);
	if (ptrace(PTRACE_GETREGS, p.child, NULL, &p.regs) < 0) ERR_QUIT("ptrace(GETREGS)");
	cout << hex << p.regs.rip << endl;
	if (ptrace(PTRACE_SINGLESTEP, p.child, 0, 0) < 0) ERR_QUIT("ptrace(SINGLESTEP)");
	wait();
}

void start() {
	if (state == RUNNING) {
		cerr << "** program \'" << p.path << "\' have already running." << endl;
		return;
	}
	if (checkstat(LOADED) < 0) return;

	pid_t child;
	if ((p.child = fork()) < 0) ERR_QUIT("fork");
	if (p.child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) ERR_QUIT("ptrace(TRACEME)");
		execlp(p.path.c_str(), p.path.c_str(), NULL);
		ERR_QUIT("execlp");
	}
	else {
		int status;
		if (waitpid(p.child, &status, 0) < 0) ERR_QUIT("wait");
		assert(WIFSTOPPED(status));
		ptrace(PTRACE_SETOPTIONS, p.child, 0, PTRACE_O_EXITKILL);
		cout << "** pid " << dec << p.child << endl;

		/* patch breakpoints */
		if (bpList != nullptr) {
			Breakpoint *tmp = bpList;
			while (tmp) {
				poketext(tmp->addr, 0xcc);
				tmp = tmp->next;
			}
		}
	}
	state = RUNNING;
}

void debugger() {
	while (1) {
		int i = 0;
		string line, comm[MAX_CMD];
		if (script.is_open()) {
			if (script.eof()) return;
			getline(script, line);
		}
		else {
			cout << "sdb> ";
			getline(cin, line);
		}

		stringstream ss(line);
		while (ss >> comm[i++] && i < MAX_CMD);
		if (comm[0] == "break" || comm[0] == "b") {
			if (!comm[1].empty())
				breakpoint(strToULL(comm[1]));
			else
				cerr << "** Syntax: break [address] (or b [address])" << endl;
		}
		else if (comm[0] == "cont" || comm[0] == "c") {
			cont();
		}
		else if (comm[0] == "delete") {
			if (!comm[1].empty())
				deletebp(strToULL(comm[1]));
			else
				cerr << "** Syntax: delete [index of breakpoint]" << endl;
		}
		else if (comm[0] == "disasm" || comm[0] == "d") {
			if (!comm[1].empty())
				disasm(comm[1]);
			else
				cerr << "** Syntax: disasm [address] (or d [address])" << endl;
		}
		else if (comm[0] == "dump" || comm[0] == "x") {
			if (!comm[1].empty())
				dump(comm[1]);
			else
				cerr << "** Syntax: dump [address] (or x [address])" << endl;
		}
		else if (comm[0] == "list" || comm[0] == "l") {
			list();
		}
		else if (comm[0] == "load") {
			if (!comm[1].empty()) {
				p.path = comm[1];
				load();
			}
			else
				cerr << "** Syntax: load [program]" << endl;
		}
		else if(comm[0] == "run") {
			run();
		}
		else if (comm[0] == "exit" || comm[0] == "q") {
			return;
		}
		else if (comm[0] == "vmmap" || comm[0] == "m") {
			vmmap();
		}
		else if (comm[0] == "set" || comm[0] == "s") {
			if (!comm[1].empty() && !comm[2].empty())
				set(comm[1], strToULL(comm[2]));
			else {
				cerr << "** Syntax: set [reg name] [value] (or s [reg name] [value])" << endl;
			}
		}
		else if (comm[0] == "si") {
			si();
		}
		else if (comm[0] == "start") {
			start();
		}
		else if (comm[0] == "get" || comm[0] == "g") {
			if (!comm[1].empty())
				get(comm[1]);
			else {
				cerr << "** Syntax: get [reg name] (or g [reg name])" << endl;
			}
		}
		else if (comm[0] == "getregs") {
			getregs();
		}
		else if (comm[0] == "help" || comm[0] == "h") {
			help();
		}
		else {
			cout << "** Error: no such command." << endl;
		}
	}
}

int main(int argc, char* argv[]){
	int opt;
	while ((opt = getopt(argc, argv, "s:")) != -1) {
        switch (opt) {
            case 's':
                script.open(optarg, fstream::in);
                break;
            default:
                cerr << "** usage: " << argv[0] << " [-s script] [program]" << endl;
                return EXIT_FAILURE;
        }
    }
	if (optind < argc) {
        p.path = argv[optind];
    }
	if (!p.path.empty()) {
		load();
	}
	debugger();
	script.close();
}