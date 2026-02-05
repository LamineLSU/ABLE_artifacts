rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D2 A9 71 E4 55 8B }  // Call RtlAllocateHeap + test eax
        $pattern1 = { 55 8B EC }          // Stack frame setup (push ebp/mov ebp, esp)
        $pattern2 = { EC 8B 45 08 }        // Memory access (in al, dx/mov eax)

    condition:
        all of them
}