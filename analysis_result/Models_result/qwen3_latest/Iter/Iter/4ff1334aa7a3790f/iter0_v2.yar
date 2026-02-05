rule CallInstructions
{
    meta:
        description = "Detects specific call instructions with address offsets"
        cape_options = "bp0=$call_exitprocess+0,action0=skip,bp1=$call_closehandle+0,action1=skip,bp2=$call_other+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-01"

    strings:
        $call_exitprocess = { 53 FF 15 ?? ?? ?? ?? }  // push ebx followed by call to ExitProcess
        $call_closehandle = { 50 FF 15 ?? ?? ?? ?? }  // push eax followed by call to CloseHandle
        $call_other = { 8B CE E8 ?? ?? ?? ?? }        // mov ecx, esi followed by call to another function

    condition:
        all of them
}