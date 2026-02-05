rule EvasionTechniques
{
    meta:
        description = "Detects potential evasion techniques using memory manipulation and control flow hijacking."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { 83 C4 14 52 FF D0 }  // add esp, 14h; push edx; call eax (leading to ExitProcess)
        $b = { 51 E8 ?? ?? ?? ?? }  // push ecx; call instruction (relative call)
        $c = { 50 51 FF D2 }  // push eax; push ecx; call edx (RtlFreeHeap)

    condition:
        any of them
}