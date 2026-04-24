rule AntiAnalysis_ExitProcess
{
    meta:
        description = "Detects or bypasses an anti-analysis mechanism that calls ExitProcess based on conditions."
        cape_options = "bp0=$test_je+0,action0=skip,bp1=$push_call+0,action1=skip,bp2=$exit_call+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2025-04-15"

    strings:
        // 1. test eax, eax followed by je (condition check)
        $test_je = { 85 C0 74 .. } // 85C0 is test eax, eax; 74 is je

        // 2. push 0 followed by call to ExitProcess
        $push_call = { 6A 00 FF 15 .. } // 6A00 is push 0; FF15 is call dword ptr

        // 3. direct call to ExitProcess (dword ptr [00432814h])
        $exit_call = { FF 15 28 43 00 00 } // FF15 is call; 28430000 is the address

    condition:
        $test_je or $push_call or $exit_call
}