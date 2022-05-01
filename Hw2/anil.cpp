/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;

ofstream OutFile;

// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 icount = 0;
static UINT64 aluCount = 0;
static UINT64 branchCount = 0;
static UINT64 memCount = 0;
static UINT64 depcount = 0;
static int last[16] = {0};
static int regFile[16] = {0};

// Notes to me
// last[2] means write
// last[1] means read
// last[0] is nothing

static std::string RegName[16] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
static REG regs[16] = {REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI, REG_RSP, REG_RBP, REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};


// This function is called before every instruction is executed
VOID mCount()
{
    memCount++;
    icount++;
}

VOID bCount()
{
    branchCount++;
    icount++;
}

VOID aCount()
{
    aluCount++;
    icount++; 
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins))    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mCount, IARG_END);
    
    else {

    if (INS_IsBranch(ins))INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)bCount, IARG_END);
    
    else    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)aCount, IARG_END);
    
    }
   
    
    for (UINT64 i = 0; i < 16; i++)
    {
        if (last[i] == 2 && INS_RegRContain(ins, regs[i]))  depcount += 1;
        
        else if (last[i] == 2 && INS_RegWContain(ins, regs[i])) depcount += 1;
        
        else if (last[i] == 1 && INS_RegWContain(ins, regs[i])) depcount += 1;
    }

    UINT64 numowregisters = INS_MaxNumWRegs(ins);

    for (UINT64 j = 0; j < numowregisters; j++)
    {

        REG reg = INS_RegW(ins, j);

        if (REG_valid(reg))
        {
            std::string shortname = REG_StringShort(reg);
            for (UINT64 i = 0; i < 16; i++)
            {
                if (shortname.compare(RegName[i]) == 0)
                {
                    regFile[i] += 1;
                    last[i] = 2; // write
                }
                else
                {
                    last[i] = 0; // nothing
                }
            }
        }
    }

    UINT64 numoRregisters = INS_MaxNumRRegs(ins);

    for (UINT64 k = 0; k < numoRregisters; k++)
    {

        REG regR = INS_RegR(ins, k);

        if (REG_valid(regR))
        {
            std::string shortname2 = REG_StringShort(regR);
            for (UINT64 i = 0; i < 16; i++)
            {
                if (shortname2.compare(RegName[i]) == 0)
                {
                    last[i] = 1; // read
                }
                else if (last[i] == 1)
                {
                    last[i] = 0; // nothing
                }
            }
        }
    }
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "anil.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile << "Total Instruction Count= " << icount << endl
            << "Memory Instruction Count= " << memCount << endl
            << "Branch Instruction Count= " << branchCount << endl
            << "Arithmatic Instruction Count= " << aluCount << endl
            << endl;

    double mPercent = memCount * 100.0 / icount;
    double bPercent = branchCount * 100.0 / icount;
    double aPercent = aluCount * 100.0 / icount;
    OutFile << "Memory Instruction Percentage= " << mPercent << "%" << endl
            << "Branch Instruction Percentage= " << bPercent << "%" << endl
            << "Arithmatic Instruction Percentage= " << aPercent << "%" << endl;

    OutFile
        << "RAX= " << regFile[0] << endl
        << "RBX= " << regFile[1] << endl
        << "RCX= " << regFile[2] << endl
        << "RDX= " << regFile[3] << endl
        << "RSI= " << regFile[4] << endl
        << "RDI= " << regFile[5] << endl
        << "RSP= " << regFile[6] << endl
        << "RBP= " << regFile[7] << endl
        << "R8= " << regFile[8] << endl
        << "R9= " << regFile[9] << endl
        << "R10= " << regFile[10] << endl
        << "R11= " << regFile[11] << endl
        << "R12= " << regFile[12] << endl
        << "R13= " << regFile[13] << endl
        << "R14= " << regFile[14] << endl
        << "R15= " << regFile[15] << endl
        << "Dependency Count= " << depcount << endl;
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl
         << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv))
        return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}