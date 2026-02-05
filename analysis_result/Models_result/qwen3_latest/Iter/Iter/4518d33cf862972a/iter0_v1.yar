rule Malicious_Termination_Logic
{
    meta:
        description = "Detects termination logic leading to ExitProcess"
        cape_options = "bp0=$test_jne+0,action0=skip,bp1=$exit_call+0,action1=skip,bp2=$vm_check_call+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2025-04-05"

    strings:
        // Pattern 1: test eax, eax followed by jne to ExitProcess
        $test_jne = { 85 C0 75 ?? } // test eax, eax followed by jne (offset replaced)

        // Pattern 2: call to ExitProcess
        $exit_call = { FF 15 ?? ?? ?? ?? } // call to ExitProcess (address replaced)

        // Pattern 3: call to a potential VM detection function
        $vm_check_call = { 8B D0 E8 ?? ?? ?? ?? } // mov edx, eax followed by call to VM check

    condition:
        $test_jne or $exit_call or $vm_check_call
}