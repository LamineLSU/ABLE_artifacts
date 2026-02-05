rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 52 8B 16 8B 16 }  // Push edx, mov edx, call RtlAllocateHeap
        $pattern1 = { 35 96 33 0C A4 77 C2 }  // XOR + JNBE conditional check
        $pattern2 = { 56 56 56 50 50 50 E8 44 09 00 00 }  // Push esi/aax + call to 0041AF30h

    condition:
        any of them
}