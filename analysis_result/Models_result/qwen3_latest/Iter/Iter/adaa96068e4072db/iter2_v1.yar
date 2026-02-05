rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 14 E8 ?? ?? ?? ?? }  // Add ESP and call to 0041F143h
        $pattern1 = { 83 C4 14 52 FF D2 }          // Add ESP, push EDX, call RtlFreeHeap
        $pattern2 = { 8B 06 52 FF D0 }            // MOV EAX, [ESI], push EDX, call ExitProcess

    condition:
        any of them
}