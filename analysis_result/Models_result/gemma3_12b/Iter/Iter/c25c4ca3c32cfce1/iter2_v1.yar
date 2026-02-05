rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 55 8B 45 08 8B 48 14 56 6A 35 6A 00 }
        $pattern2 = { 83 F8 01 74 12 8B 4D }

    condition:
        any of them
}