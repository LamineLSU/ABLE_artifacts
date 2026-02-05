rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 84 C0 74 20 }  // Call + test al, al + je
        $pattern1 = { FF 15 ?? ?? ?? ?? 85 C0 74 23 }  // API call + test eax, eax + je
        $pattern2 = { FF 15 ?? ?? ?? ?? 85 F6 74 0D }  // API call + test esi, esi + je

    condition:
        any of them
}