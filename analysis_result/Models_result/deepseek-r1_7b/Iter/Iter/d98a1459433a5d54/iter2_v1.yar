rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit checks and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 74 12 8B 45 FC }
        $pattern1 = { E8 E3 FA FF FF 00 84 5E 83 }
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 }

    condition:
        any of them
}