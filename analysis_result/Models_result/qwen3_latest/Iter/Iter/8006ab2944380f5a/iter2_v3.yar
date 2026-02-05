rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 51 FF D2 83 C4 04 }  // push eax, push ecx, call edx, add esp
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 04 }  // call [offset], add esp
        $pattern2 = { 52 FF D0 83 C4 04 }  // push edx, call eax, add esp

    condition:
        any of them
}