rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 51 FF D2 }  // Push EAX/ECX + Call RtlAllocateHeap
        $pattern1 = { 6A 36 6A 00 51 51 E8 ?? ?? ?? ?? }  // Push 36h/00 + Push ECX + Call (offset wildcards)
        $pattern2 = { 8B 06 83 C4 14 FF D2 }  // MOV EAX + ADD ESP + Call RtlFreeHeap

    condition:
        any of them
}