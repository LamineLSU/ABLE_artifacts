rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 55 14 }  // Call to 0041F143h followed by mov edx
        $pattern1 = { 52 FF D2 5E }                // Call to edx (RtlFreeHeap) with push/pop
        $pattern2 = { 52 FF D0 5E }                // Call to eax (ExitProcess) with push/pop

    condition:
        any of them
}