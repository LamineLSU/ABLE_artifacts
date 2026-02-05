rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting stack manipulation and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5B 5A 8B CE E8 ?? 00 90 A1 2C ?? 00 90 A1 2C }
        $pattern2 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 8B 40 68 }

    condition:
        any of them
}