rule bypass_exit_process
{
    meta:
        description = "Bypasses the call to ExitProcess by targeting critical instructions in the disassembly trace."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { 52 FF D0 ?? ?? ?? ?? }  // Push EDX, Call EAX (ExitProcess)
        $b = { 56 E8 ?? ?? ?? ?? }      // Push ESI, Call (to 0041EB17)
        $c = { 83 C4 14 52 FF D0 ?? ?? ?? ?? }  // Add ESP, Push EDX, Call EAX (ExitProcess)

    condition:
        any of ($a, $b, $c)
}