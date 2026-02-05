rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { ?? ?? ?? ?? ?? ?? FF D2 5E 5D C3 }  // RtlAllocateHeap call + RET sequence
        $pattern1 = { ?? ?? ?? ?? ?? ?? A9 C5 1E B6 55 }  // TEST instruction with hardcoded value
        $pattern2 = { ?? ?? ?? ?? ?? ?? 8B 16 50 50 }      // MOV + PUSH sequence for stack setup

    condition:
        any of them
}