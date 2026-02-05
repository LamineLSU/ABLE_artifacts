rule bypass_exit_call
{
    meta:
        description = "Bypasses an exit call by detecting specific instruction sequences"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 83 C4 ?? 52 FF D0 }  // add esp, 14h followed by push edx and call eax
        $b = { E8 ?? ?? ?? ?? 8B 55 ?? 83 C4 ?? }  // call to 0041EB27 followed by mov and add instructions
        $c = { 56 50 E8 ?? ?? ?? ?? }  // push esi, push eax, and call instruction
    
    condition:
        all of ($a or $b or $c)
}