rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 74 10 }  // Call + test + je (IsWindowVisible check)
        $pattern1 = { 83 7D 10 00 75 32 }                // cmp [ebp+10h], 0 + jne
        $pattern2 = { FF 15 ?? ?? ?? ?? }               // Generic call to exit-related API

    condition:
        any of them
}