rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using specific exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? 8B CE }
        $pattern1 = { 85 C0 E8 4F ?? ?? ?? ?? ?? }
        $pattern2 = { E8 0D 0C 00 00 8B 4D FC E8 57 26 00 00 }

    condition:
        any of them
}