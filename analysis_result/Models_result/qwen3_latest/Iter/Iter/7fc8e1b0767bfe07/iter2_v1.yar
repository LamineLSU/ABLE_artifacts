rule ProcessTerminationPattern
{
    meta:
        description = "Detects an attempt to terminate a process by calling ExitProcess, often used in malware or malicious code."
        cape_options = "bp0=$test_jne+0,action0=skip,bp1=$test_je+0,action1=skip,bp2=$call_exitprocess+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $test_jne = { 85 C0 74 ?? ?? ?? ?? }  // test eax, eax followed by jne
        $test_je = { 85 C0 0F 84 ?? ?? ?? ?? }  // test eax, eax followed by je
        $call_exitprocess = { FF 15 ?? ?? ?? ?? ?? }  // call to ExitProcess

    condition:
        all of them
}