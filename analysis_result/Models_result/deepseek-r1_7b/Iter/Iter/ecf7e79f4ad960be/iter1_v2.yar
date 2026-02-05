rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - target conditional checks before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? 74 12 01 37 61 90 }
        $pattern1 = { 85 C0 0F 84 ?? ?? 74 12 01 37 61 B7 }
        $pattern2 = { 85 C0 0F 84 ?? ?? 74 12 01 37 61 E5 }

    condition:
        any of them
}