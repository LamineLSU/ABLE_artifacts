rule ExampleRule {
    meta:
        description = "Detects specific call instructions and their surrounding context"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 53 FF 15 ?? ?? ?? ?? } // push ebx followed by call to ExitProcess
        $b = { 50 FF 15 ?? ?? ?? ?? } // push eax followed by call to CloseHandle
        $c = { E8 ?? ?? ?? ?? }       // call instruction with displacement
    condition:
        any of them
}