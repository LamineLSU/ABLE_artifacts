rule MalwareExitPattern
{
    meta:
        description = "Detects patterns leading to early exit via ExitProcess call"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 53 E8 ?? ?? ?? ?? }  // push ebx followed by call to ExitProcess
        $b = { 50 E8 ?? ?? ?? ?? }  // push eax followed by call to CloseHandle
        $c = { 85 C0 74 ?? }        // test eax, eax followed by je (conditional jump)
    condition:
        all of them
}