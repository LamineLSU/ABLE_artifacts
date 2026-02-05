rule WindowsAPIFunctionCalls
{
    meta:
        description = "Detects calls to Windows API functions like ExitProcess and RtlFreeHeap, along with associated memory manipulation."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2025-04-05"
        platform = "Windows"

    strings:
        $a = { 83 C4 14 52 FF D0 } // add esp, 14h; push edx; call eax (ExitProcess)
        $b = { 8B 16 50 51 FF D2 } // mov edx, [esi]; push eax; push ecx; call edx (RtlFreeHeap)
        $c = { 8D 44 04 ?? ?? ?? ?? 50 FF D2 } // lea esi, [eax+...] (displacement is an address); push esi; call edx (RtlFreeHeap)

    condition:
        $a or $b or $c
}