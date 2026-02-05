rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 55 14 }  // Call to 0041F143h followed by mov edx
        $pattern1 = { 8B 16 50 51 FF D0 }          // Dynamic call to RtlFreeHeap
        $pattern2 = { 83 C4 14 52 FF D0 }          // Dynamic call to ExitProcess

    condition:
        any of them
}